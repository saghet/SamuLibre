package org.samulibre.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private val vpnRequestCode = 101

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Inicializar SamuLibre Native Core en hilo secundario
        CoroutineScope(Dispatchers.IO).launch {
            val dataDir = applicationContext.filesDir.absolutePath
            NativeBridge.initCore(dataDir)
        }

        webView = WebView(this).apply {
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                allowFileAccess = true
                allowContentAccess = true
                loadsImagesAutomatically = true
                cacheMode = WebSettings.LOAD_DEFAULT
                useWideViewPort = true
                loadWithOverviewMode = true
            }
            webChromeClient = WebChromeClient()
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    injectMobileEnvironment()
                }
            }
            addJavascriptInterface(WebAppInterface(), "AndroidBridge")
        }

        setContentView(webView)
        webView.loadUrl("file:///android_asset/ui/index.html")
    }

    private fun injectMobileEnvironment() {
        val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Build.VERSION.SECURITY_PATCH
        } else {
            "2020-01-01"
        }

        val kernelVersion = System.getProperty("os.version") ?: "unknown"
        val isRooted = checkRootMethod()

        val deviceInfo = JSONObject().apply {
            put("sdk_int", Build.VERSION.SDK_INT)
            put("release_version", Build.VERSION.RELEASE)
            put("security_patch_level", securityPatch)
            put("kernel_version", kernelVersion)
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("is_root_detected", isRooted)
            put("unpatched_asb_cves", JSONArray())
            put("active_tun_rules_count", 0)
            put("overlay_shield_active", true)
            put("accessibility_guard_active", true)
        }

        val script = """
            (function() {
                window.isAndroidApp = true;
                window.androidSecurityInfo = $deviceInfo;
                window.ipc = {
                    postMessage: function(msg) {
                        var str = typeof msg === 'string' ? msg : JSON.stringify(msg);
                        var rawRes = window.AndroidBridge.postMessage(str);
                        if (rawRes) {
                            try {
                                var res = JSON.parse(rawRes);
                                if (window.dispatchAndroidIpcCallback) {
                                    window.dispatchAndroidIpcCallback(res);
                                }
                            } catch(e) {
                                console.error("IPC dispatch error:", e);
                            }
                        }
                        return rawRes;
                    }
                };
                console.log("SamuLibre Android Environment Injected Successfully.");
                if (window.dispatchEvent) {
                    window.dispatchEvent(new CustomEvent('samulibre-android-ready', { detail: window.androidSecurityInfo }));
                }
            })();
        """.trimIndent()

        webView.evaluateJavascript(script, null)
    }

    private fun checkRootMethod(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        return paths.any { java.io.File(it).exists() }
    }

    private fun startVpnService() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, vpnRequestCode)
        } else {
            onActivityResult(vpnRequestCode, Activity.RESULT_OK, null)
        }
    }

    private fun stopVpnService() {
        val serviceIntent = Intent(this, SamuVpnService::class.java).apply {
            action = SamuVpnService.ACTION_STOP
        }
        startService(serviceIntent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequestCode && resultCode == Activity.RESULT_OK) {
            val serviceIntent = Intent(this, SamuVpnService::class.java).apply {
                action = SamuVpnService.ACTION_START
            }
            startService(serviceIntent)
        }
    }

    inner class WebAppInterface {
        @JavascriptInterface
        fun postMessage(jsonString: String): String {
            return try {
                val json = JSONObject(jsonString)
                val action = json.optString("action")

                if (action == "start_vpn_shield") {
                    runOnUiThread { startVpnService() }
                    return JSONObject().apply {
                        put("success", true)
                        put("message", "Solicitando autorización de VpnService")
                    }.toString()
                }

                if (action == "connect_vpn") {
                    runOnUiThread { startVpnService() }
                    return NativeBridge.dispatchIpc(jsonString)
                }

                if (action == "disconnect_vpn") {
                    runOnUiThread { stopVpnService() }
                    return NativeBridge.dispatchIpc(jsonString)
                }

                if (action == "audit_device_apps") {
                    val packages = getInstalledAppsDetails()
                    val req = JSONObject().apply {
                        put("action", "audit_android_packages")
                        put("payload", packages.toString())
                    }
                    return NativeBridge.dispatchIpc(req.toString())
                }

                NativeBridge.dispatchIpc(jsonString)
            } catch (e: Exception) {
                JSONObject().apply {
                    put("success", false)
                    put("error", e.message)
                }.toString()
            }
        }

        private fun getInstalledAppsDetails(): JSONArray {
            val pm = packageManager
            val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            val result = JSONArray()

            for (pkg in packages) {
                val appInfo = pkg.applicationInfo ?: continue
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

                val reqPerms = pkg.requestedPermissions ?: emptyArray()
                val hasOverlay = reqPerms.contains("android.permission.SYSTEM_ALERT_WINDOW")
                val hasAccessibility = reqPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")

                val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    try {
                        pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                    } catch (e: Exception) {
                        null
                    }
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(pkg.packageName)
                }

                val item = JSONObject().apply {
                    put("package_name", pkg.packageName)
                    put("app_name", appInfo.loadLabel(pm).toString())
                    put("version_name", pkg.versionName ?: "1.0")
                    put("is_system_app", isSystem)
                    put("installer_package_name", installer)
                    put("requested_permissions", JSONArray(reqPerms.toList()))
                    put("has_overlay_permission", hasOverlay)
                    put("has_accessibility_service", hasAccessibility)
                    put("apk_path", appInfo.sourceDir)
                    put("sha256", null as String?)
                }
                result.put(item)
            }
            return result
        }
    }

    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
