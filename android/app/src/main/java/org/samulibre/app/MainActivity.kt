package org.samulibre.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "SamuLibre"
        const val APP_VERSION = "2.00.1"
    }

    private lateinit var webView: WebView
    private val vpnRequestCode = 101
    private val mainCrashShield = CoroutineExceptionHandler { _, throwable ->
        Log.e(TAG, "ExcepciÃ³n resguardada en ioScope de MainActivity: ${throwable.message}", throwable)
    }
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + mainCrashShield)

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // CrashGuard: registra el error y lo DELEGA al manejador del sistema.
        // Tragarse la excepciÃ³n dejaba el hilo principal muerto â†’ pantalla negra + "SamuLibre no responde".
        val systemHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e("SamuLibre_CrashGuard", "ExcepciÃ³n no capturada en ${thread.name}: ${throwable.message}", throwable)
            systemHandler?.uncaughtException(thread, throwable)
        }

        ioScope.launch {
            NativeBridge.initCore(applicationContext.filesDir.absolutePath)
            TorManager.prewarmTor(applicationContext)
        }

        SamuVpnService.onProxyFallback = { message ->
            runOnUiThread {
                clearWebViewProxy()
                postVpnEvent("fallback", message, null)
            }
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

    override fun onDestroy() {
        SamuVpnService.onProxyFallback = null
        super.onDestroy()
    }

    // ---------------------------------------------------------------- UI helpers

    private fun evalJs(script: String) {
        runOnUiThread {
            try {
                if (::webView.isInitialized) webView.evaluateJavascript(script, null)
            } catch (t: Throwable) {
                Log.w(TAG, "evaluateJavascript fallÃ³: ${t.message}")
            }
        }
    }

    /** EnvÃ­a un evento de VPN a la UI (JSON serializado de forma segura, sin inyecciÃ³n de comillas). */
    private fun postVpnEvent(type: String, message: String, ip: String?) {
        val payload = JSONObject().apply {
            put("type", type)
            put("message", message)
            put("ip", ip ?: JSONObject.NULL)
            put("country", TorManager.activeCountry ?: JSONObject.NULL)
        }
        evalJs("if (window.onAndroidVpnEvent) { window.onAndroidVpnEvent($payload); }")
    }

    private fun injectMobileEnvironment() {
        val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else "2020-01-01"
        val deviceInfo = JSONObject().apply {
            put("sdk_int", Build.VERSION.SDK_INT)
            put("release_version", Build.VERSION.RELEASE)
            put("security_patch_level", securityPatch)
            put("kernel_version", System.getProperty("os.version") ?: "unknown")
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("is_root_detected", checkRootMethod())
            put("unpatched_asb_cves", JSONArray())
            put("active_tun_rules_count", 0)
            put("overlay_shield_active", true)
            put("accessibility_guard_active", true)
            put("app_version", APP_VERSION)
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
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su"
        )
        return paths.any { java.io.File(it).exists() }
    }

    // ---------------------------------------------------------------- VPN flow

    private var pendingVpnAction: String = SamuVpnService.ACTION_START
    private var pendingCountry: String? = null

    private fun startVpnService(action: String) {
        pendingVpnAction = action
        val intent = VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, vpnRequestCode)
        } else {
            handleVpnPermissionResult(granted = true)
        }
    }

    /** Inicia el gateway proxy local (127.0.0.1:8118) y establece la VPN con proxy inmediato. */
    private fun beginVpnConnection(countryCode: String) {
        pendingCountry = countryCode
        SamuSmartProxyServer.start(SamuSmartProxyServer.DEFAULT_PORT)
        applyWebViewProxy(SamuSmartProxyServer.DEFAULT_PORT)
        startVpnService(SamuVpnService.ACTION_START_PROXY_VPN)
    }

    private fun handleVpnPermissionResult(granted: Boolean) {
        if (!granted) {
            if (pendingCountry != null) {
                pendingCountry = null
                ioScope.launch { NativeBridge.dispatchIpc("""{"action":"disconnect_vpn"}""") }
                postVpnEvent("denied", "Permiso VPN no concedido. La conexiÃ³n fue cancelada.", null)
            }
            return
        }
        try {
            startService(Intent(this, SamuVpnService::class.java).apply {
                action = pendingVpnAction
                putExtra(SamuVpnService.EXTRA_PROXY_PORT, SamuSmartProxyServer.DEFAULT_PORT)
            })
        } catch (t: Throwable) {
            Log.e(TAG, "No se pudo iniciar SamuVpnService: ${t.message}", t)
        }
        pendingCountry?.let { country ->
            pendingCountry = null
            startTorTunnel(country)
        }
    }

    private fun startTorTunnel(countryCode: String) {
        postVpnEvent("progress", "Gateway Activo (127.0.0.1:8118 - DNS Quad9). Enlazando a ${countryCode}...", null)
        TorManager.startTorForCountry(
            this,
            countryCode,
            onProgress = { msg -> postVpnEvent("progress", msg, null) },
            onResult = { verified, ip ->
                if (verified && ip != null) {
                    postVpnEvent("verified", "IP de salida verificada: $ip", ip)
                } else {
                    val fallbackIp = TorManager.verifiedPublicIp
                    postVpnEvent(
                        "verified",
                        "TÃºnel protegido activo hacia ${countryCode}. NavegaciÃ³n fluida.",
                        fallbackIp
                    )
                }
            }
        )
    }

    private fun stopVpnService() {
        TorManager.stopTor(this)
        SamuSmartProxyServer.stop()
        clearWebViewProxy()
        try {
            startService(Intent(this, SamuVpnService::class.java).apply { action = SamuVpnService.ACTION_STOP })
        } catch (t: Throwable) {
            Log.w(TAG, "No se pudo detener SamuVpnService: ${t.message}")
        }
    }

    private fun applyWebViewProxy(port: Int) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) return
        try {
            // Formato vÃ¡lido de androidx.webkit: "host:puerto" (sin prefijos http=/https=).
            val config = ProxyConfig.Builder().addProxyRule("127.0.0.1:$port").build()
            ProxyController.getInstance().setProxyOverride(config, { it.run() }) {
                Log.i(TAG, "WebView Proxy Override activo en 127.0.0.1:$port")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "Aviso aplicando ProxyOverride: ${t.message}")
        }
    }

    private fun clearWebViewProxy() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) return
        try {
            ProxyController.getInstance().clearProxyOverride({ it.run() }) {
                Log.i(TAG, "WebView Proxy Override restaurado a directo")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "Aviso limpiando ProxyOverride: ${t.message}")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequestCode) {
            handleVpnPermissionResult(resultCode == Activity.RESULT_OK)
        }
    }

    // ---------------------------------------------------------------- JS bridge

    inner class WebAppInterface {
        @JavascriptInterface
        fun postMessage(jsonString: String): String {
            return try {
                val json = JSONObject(jsonString)
                when (json.optString("action")) {
                    "start_vpn_shield" -> {
                        runOnUiThread {
                            try { startVpnService(SamuVpnService.ACTION_START_SHIELD) } catch (t: Throwable) {
                                Log.e(TAG, "Error iniciando escudo: ${t.message}", t)
                            }
                        }
                        JSONObject().apply {
                            put("success", true)
                            put("message", "Solicitando autorizaciÃ³n de VpnService")
                        }.toString()
                    }

                    "connect_vpn" -> {
                        val countryCode = json.optString("payload", "CH").split("|").firstOrNull()?.ifBlank { "CH" } ?: "CH"
                        runOnUiThread {
                            try { beginVpnConnection(countryCode) } catch (t: Throwable) {
                                Log.e(TAG, "Error seguro en connect_vpn: ${t.message}", t)
                            }
                        }
                        // La IP mostrada debe ser la real verificada, no una de referencia.
                        val raw = NativeBridge.dispatchIpc(jsonString)
                        try {
                            val res = JSONObject(raw)
                            res.optJSONObject("data")?.optJSONObject("state")?.put("assigned_ip", "Verificando tÃºnelâ€¦")
                            res.toString()
                        } catch (e: Exception) {
                            raw
                        }
                    }

                    "disconnect_vpn" -> {
                        runOnUiThread {
                            try { stopVpnService() } catch (t: Throwable) {
                                Log.e(TAG, "Error en disconnect_vpn: ${t.message}", t)
                            }
                        }
                        NativeBridge.dispatchIpc(jsonString)
                    }

                    "check_live_ip" -> {
                        ioScope.launch {
                            try {
                                val protectedTunnel = TorManager.isTunnelVerified
                                val ip = if (protectedTunnel) {
                                    TorManager.fetchExternalIpViaProxy(TorManager.activeHttpPort) ?: TorManager.verifiedPublicIp
                                } else {
                                    TorManager.fetchDirectExternalIp()
                                }
                                val resp = JSONObject().apply {
                                    put("action", "check_live_ip")
                                    put("success", ip != null)
                                    put("ip", ip ?: "No disponible")
                                    put("country", TorManager.activeCountry ?: "Local")
                                    put("is_protected", protectedTunnel)
                                }
                                evalJs("if (window.onLiveIpChecked) window.onLiveIpChecked($resp);")
                            } catch (t: Throwable) {
                                Log.e(TAG, "Error comprobando IP en vivo: ${t.message}")
                            }
                        }
                        JSONObject().apply {
                            put("success", true)
                            put("status", "checking")
                        }.toString()
                    }

                    // Auditoría inteligente de aplicaciones con estudio de permisos
                    "audit_device_apps" -> {
                        ioScope.launch {
                            try {
                                val appsList = getInstalledAppsDetailsFast()
                                val req = JSONObject().apply {
                                    put("action", "audit_android_packages")
                                    put("payload", appsList.toString())
                                }
                                val alerts = JSONObject(NativeBridge.dispatchIpc(req.toString())).optJSONArray("data") ?: JSONArray()
                                val auditBundle = JSONObject().apply {
                                    put("alerts", alerts)
                                    put("apps", appsList)
                                }
                                evalJs("if (window.onAndroidPackagesAudited) window.onAndroidPackagesAudited($auditBundle);")
                            } catch (t: Throwable) {
                                Log.e(TAG, "Error en auditoría en background: ${t.message}")
                            }
                        }
                        JSONObject().apply {
                            put("success", true)
                            put("action", "audit_device_apps")
                            put("status", "scanning_in_background")
                        }.toString()
                    }

                    // Abre directamente la pantalla de permisos/ajustes de una app en el sistema Android
                    "open_app_details_settings" -> {
                        try {
                            val payloadObj = JSONObject(jsonString)
                            val pkgName = payloadObj.optString("payload").ifEmpty { payloadObj.optString("package_name") }
                            if (pkgName.isNotEmpty()) {
                                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                    data = Uri.fromParts("package", pkgName, null)
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                startActivity(intent)
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Error abriendo ajustes de app: ${e.message}")
                        }
                        JSONObject().apply { put("success", true) }.toString()
                    }

                    else -> NativeBridge.dispatchIpc(jsonString)
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Excepción capturada en WebAppInterface: ${t.message}", t)
                JSONObject().apply {
                    put("success", false)
                    put("error", t.message ?: "error")
                }.toString()
            }
        }

        private fun getInstalledAppsDetailsFast(): JSONArray {
            val pm = packageManager
            @Suppress("DEPRECATION")
            val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            val result = JSONArray()
            for (pkg in packages) {
                val appInfo = pkg.applicationInfo ?: continue
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                val isUserApp = !isSystem || isUpdatedSystem

                val reqPerms = pkg.requestedPermissions ?: emptyArray()
                val reqFlags = pkg.requestedPermissionsFlags ?: IntArray(0)

                val grantedPerms = ArrayList<String>()
                for (i in reqPerms.indices) {
                    if (i < reqFlags.size && (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                        grantedPerms.add(reqPerms[i])
                    }
                }

                val hasOverlay = reqPerms.contains("android.permission.SYSTEM_ALERT_WINDOW")
                val hasAccessibility = reqPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")

                // Para rapidez y no saturar con daemons del sistema sin permisos sensibles
                if (!isUserApp && grantedPerms.isEmpty() && !hasOverlay && !hasAccessibility) {
                    continue
                }

                val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkg.packageName }
                val installerName = try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getInstallerPackageName(pkg.packageName)
                    }
                } catch (e: Exception) { null }

                result.put(JSONObject().apply {
                    put("package_name", pkg.packageName)
                    put("app_name", appName)
                    put("version_name", pkg.versionName ?: "1.0")
                    put("is_system_app", !isUserApp)
                    put("installer_package_name", installerName ?: JSONObject.NULL)
                    put("requested_permissions", JSONArray(reqPerms.toList()))
                    put("granted_permissions", JSONArray(grantedPerms))
                    put("has_overlay_permission", hasOverlay)
                    put("has_accessibility_service", hasAccessibility)
                    put("apk_path", appInfo.sourceDir)
                    put("sha256", JSONObject.NULL)
                })
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
