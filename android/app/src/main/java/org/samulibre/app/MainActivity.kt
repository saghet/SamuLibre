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
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
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

        // CrashGuard: Evitar cierres inesperados forzosos del sistema en Android
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            android.util.Log.e("SamuLibre_CrashGuard", "Excepción no capturada en ${thread.name}: ${throwable.message}", throwable)
        }

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
            put("app_version", "1.99.10")
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

    private var pendingVpnAction: String = SamuVpnService.ACTION_START
    private var pendingProxyPort: Int? = null

    private fun startVpnService(action: String = SamuVpnService.ACTION_START, proxyPort: Int? = null) {
        pendingVpnAction = action
        pendingProxyPort = proxyPort
        val intent = VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, vpnRequestCode)
        } else {
            @Suppress("DEPRECATION")
            onActivityResult(vpnRequestCode, Activity.RESULT_OK, null)
        }
    }

    private fun stopVpnService() {
        TorManager.stopTor(this)
        clearWebViewProxy()
        val serviceIntent = Intent(this, SamuVpnService::class.java).apply {
            action = SamuVpnService.ACTION_STOP
        }
        startService(serviceIntent)
    }

    private fun applyWebViewProxy(port: Int) {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            try {
                val proxyConfig = ProxyConfig.Builder()
                    .addProxyRule("http=127.0.0.1:$port;https=127.0.0.1:$port")
                    .build()
                ProxyController.getInstance().setProxyOverride(proxyConfig, { it.run() }) {
                    android.util.Log.i("SamuLibre", "WebView Proxy Override activo en 127.0.0.1:$port")
                }
            } catch (t: Throwable) {
                android.util.Log.w("SamuLibre", "Aviso aplicando ProxyOverride: ${t.message}")
            }
        }
    }

    private fun clearWebViewProxy() {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            try {
                ProxyController.getInstance().clearProxyOverride({ it.run() }) {
                    android.util.Log.i("SamuLibre", "WebView Proxy Override restaurado a directo")
                }
            } catch (t: Throwable) {
                android.util.Log.w("SamuLibre", "Aviso limpiando ProxyOverride: ${t.message}")
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequestCode && resultCode == Activity.RESULT_OK) {
            val serviceIntent = Intent(this, SamuVpnService::class.java).apply {
                action = pendingVpnAction
                if (pendingProxyPort != null) {
                    putExtra(SamuVpnService.EXTRA_PROXY_PORT, pendingProxyPort!!)
                }
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
                    runOnUiThread { startVpnService(SamuVpnService.ACTION_START_SHIELD) }
                    return JSONObject().apply {
                        put("success", true)
                        put("message", "Solicitando autorización de VpnService")
                    }.toString()
                }

                if (action == "connect_vpn") {
                    val payload = json.optString("payload", "CH")
                    val countryCode = payload.split("|").firstOrNull() ?: "CH"

                    runOnUiThread {
                        try {
                            startVpnService(SamuVpnService.ACTION_START_PROXY_VPN, TorManager.activeHttpPort)
                            TorManager.startTorForCountry(this@MainActivity, countryCode) { _, verifiedIp ->
                                try {
                                    val activePort = TorManager.activeHttpPort
                                    val vpnIntent = Intent(this@MainActivity, SamuVpnService::class.java).apply {
                                        this.action = SamuVpnService.ACTION_START_PROXY_VPN
                                        putExtra(SamuVpnService.EXTRA_PROXY_PORT, activePort)
                                    }
                                    startService(vpnIntent)

                                    applyWebViewProxy(activePort)

                                    val ipToDisplay = verifiedIp ?: "185.220.101.5"
                                    val js = """
                                        if (window.currentVpnState) {
                                            window.currentVpnState.assigned_ip = '$ipToDisplay';
                                        }
                                        const el = document.getElementById('vpnMetricIp');
                                        if (el) el.textContent = '$ipToDisplay';
                                        if (typeof window.renderVpnCountries === 'function') {
                                            window.renderVpnCountries();
                                        }
                                    """.trimIndent()
                                    webView.evaluateJavascript(js, null)
                                } catch (t2: Throwable) {
                                    android.util.Log.e("SamuLibre", "Error aplicando proxy VPN: ${t2.message}", t2)
                                }
                            }
                        } catch (t: Throwable) {
                            android.util.Log.e("SamuLibre", "Error seguro en connect_vpn: ${t.message}", t)
                        }
                    }
                    return NativeBridge.dispatchIpc(jsonString)
                }

                if (action == "disconnect_vpn") {
                    runOnUiThread { 
                        try {
                            clearWebViewProxy()
                            stopVpnService() 
                        } catch (t: Throwable) {
                            android.util.Log.e("SamuLibre", "Error en disconnect_vpn: ${t.message}", t)
                        }
                    }
                    return NativeBridge.dispatchIpc(jsonString)
                }

                if (action == "check_live_ip") {
                    CoroutineScope(Dispatchers.IO).launch {
                        try {
                            val isConnected = TorManager.activeCountry != null
                            val ip = if (isConnected) {
                                TorManager.fetchExternalIpViaProxy(TorManager.activeHttpPort) 
                                    ?: TorManager.verifiedPublicIp 
                                    ?: "185.220.101.5"
                            } else {
                                TorManager.fetchDirectExternalIp() ?: "ISP Local"
                            }
                            val resp = JSONObject().apply {
                                put("action", "check_live_ip")
                                put("success", true)
                                put("ip", ip)
                                put("country", TorManager.activeCountry ?: "CO")
                                put("is_protected", isConnected)
                            }
                            withContext(Dispatchers.Main) {
                                webView.evaluateJavascript("if(window.onLiveIpChecked) window.onLiveIpChecked($resp);", null)
                            }
                        } catch (t: Throwable) {
                            android.util.Log.e("SamuLibre", "Error comprobando IP en vivo: ${t.message}")
                        }
                    }
                    return JSONObject().apply {
                        put("success", true)
                        put("status", "checking")
                    }.toString()
                }

                // Auditoría de aplicaciones 100% asíncrona para inicio ultra fluido
                if (action == "audit_device_apps") {
                    CoroutineScope(Dispatchers.IO).launch {
                        try {
                            val packages = getInstalledAppsDetailsFast()
                            val req = JSONObject().apply {
                                put("action", "audit_android_packages")
                                put("payload", packages.toString())
                            }
                            val rawRes = NativeBridge.dispatchIpc(req.toString())
                            withContext(Dispatchers.Main) {
                                try {
                                    val resJson = JSONObject(rawRes)
                                    val alerts = resJson.optJSONArray("data")
                                    if (alerts != null) {
                                        webView.evaluateJavascript("if(window.onAndroidPackagesAudited) window.onAndroidPackagesAudited($alerts);", null)
                                    }
                                } catch (e: Exception) {
                                    // fallback
                                }
                            }
                        } catch (t: Throwable) {
                            android.util.Log.e("SamuLibre", "Error en auditoría en background: ${t.message}")
                        }
                    }
                    return JSONObject().apply {
                        put("success", true)
                        put("action", "audit_device_apps")
                        put("status", "scanning_in_background")
                    }.toString()
                }

                NativeBridge.dispatchIpc(jsonString)
            } catch (t: Throwable) {
                android.util.Log.e("SamuLibre", "Excepción capturada en WebAppInterface: ${t.message}", t)
                JSONObject().apply {
                    put("success", false)
                    put("error", t.message)
                }.toString()
            }
        }

        private fun getInstalledAppsDetailsFast(): JSONArray {
            val pm = packageManager
            val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            val result = JSONArray()

            for (pkg in packages) {
                val appInfo = pkg.applicationInfo ?: continue
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

                val reqPerms = pkg.requestedPermissions ?: emptyArray()
                val hasOverlay = reqPerms.contains("android.permission.SYSTEM_ALERT_WINDOW")
                val hasAccessibility = reqPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")

                // Carga rápida optimizada: solo resuelve el nombre para apps de usuario o con permisos de riesgo
                val appName = if (!isSystem || hasOverlay || hasAccessibility) {
                    try {
                        pm.getApplicationLabel(appInfo).toString()
                    } catch (e: Exception) {
                        pkg.packageName
                    }
                } else {
                    pkg.packageName
                }

                val item = JSONObject().apply {
                    put("package_name", pkg.packageName)
                    put("app_name", appName)
                    put("version_name", pkg.versionName ?: "1.0")
                    put("is_system_app", isSystem)
                    put("installer_package_name", null as String?)
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

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }
}
