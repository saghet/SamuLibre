package org.samulibre.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.app.NotificationManager
import android.content.Context
import android.widget.Toast
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import java.io.File
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
        const val APP_VERSION = "2.01.13"
    }

    private lateinit var webView: WebView
    private val vpnRequestCode = 101
    private val uninstallRequestCode = 202
    private val mainCrashShield = CoroutineExceptionHandler { _, throwable ->
        Log.e(TAG, "ExcepciÃ³n resguardada en ioScope de MainActivity: ${throwable.message}", throwable)
    }
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + mainCrashShield)
    private var activeScanJob: kotlinx.coroutines.Job? = null
    private val isScanActive = java.util.concurrent.atomic.AtomicBoolean(false)
    private var lastRequestedUninstallPkg: String? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // CrashGuard: registra el error y lo DELEGA al manejador del sistema.
        // Tragarse la excepciÃ³n dejaba el hilo principal muerto â†’ pantalla negra + "SamuLibre no responde".
        val systemHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e("SamuLibre_CrashGuard", "Excepción no capturada en ${thread.name}: ${throwable.message}", throwable)
            if (android.os.Looper.getMainLooper().thread == thread) {
                systemHandler?.uncaughtException(thread, throwable)
            }
        }

        ioScope.launch {
            NativeBridge.initCore(applicationContext.filesDir.absolutePath)
            try {
                val initAuditReq = JSONObject().apply {
                    put("action", "audit_android_security")
                    put("payload", getDeviceSecurityInfoJson().toString())
                }
                NativeBridge.dispatchIpc(initAuditReq.toString())
            } catch (e: Exception) {
                Log.w(TAG, "Error en auditoría inicial tras initCore: ${e.message}")
            }
            // Tor se inicia bajo demanda al conectar VPN para mantener el arranque ultra liviano a 60 FPS
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
                useWideViewPort = false
                loadWithOverviewMode = false
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
                // Solicitar permiso de notificaciones en tiempo de ejecución (Android 13+ / API 33+)
        // Esto garantiza que el icono en la barra de estado y el menú desplegable se muestren inmediatamente
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2002)
            }
        }

        // Iniciar el Escudo Cyber-Shield de inmediato en primer plano (estilo Bitdefender)
        // para que el icono protector y la tarjeta de conexión rápida estén SIEMPRE visibles arriba
        // desde la primera apertura de la aplicación.
        startCyberShieldService()
        checkAutoConnectVpn(intent)

        // Inicialización Asíncrona en Segundo Plano (Zero UI Thread Blocking / Zero ANR)
        ioScope.launch {
            try {
                AndroidThreatDatabase.loadDynamicSignatures(applicationContext)
            } catch (t: Throwable) {
                Log.w(TAG, "Error resguardado cargando firmas dinámicas: ${t.message}")
            }

            try {
                RealtimeDownloadObserver.startWatching(applicationContext) { threatJson ->
                    runOnUiThread {
                        evalJs("if (window.onRealtimeApkThreatDetected) { window.onRealtimeApkThreatDetected($threatJson); }")
                    }
                }
            } catch (t: Throwable) {
                Log.w(TAG, "Error resguardado iniciando RealtimeDownloadObserver: ${t.message}")
            }

            try {
                SamuScanScheduler.checkAndRunIfDue(applicationContext)
                SamuScanScheduler.scheduleNextScan(applicationContext, forceReset = false)
            } catch (t: Throwable) {
                Log.w(TAG, "Error resguardado en SamuScanScheduler: ${t.message}")
            }

            withContext(Dispatchers.Main) {
                evalJs("if (window.loadScheduledScanUI) window.loadScheduledScanUI();")
            }
        }

        webView.loadUrl("file:///android_asset/ui/index.html")
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        checkAutoConnectVpn(intent)

        if (intent?.action == RealtimeDownloadObserver.ACTION_DELETE_DOWNLOADED_APK) {
            val filePath = intent.getStringExtra(RealtimeDownloadObserver.EXTRA_THREAT_FILE_PATH)
            if (!filePath.isNullOrEmpty()) {
                val f = java.io.File(filePath)
                val deleted = try { f.exists() && f.delete() } catch (e: Exception) { false }
                if (deleted) {
                    val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
                    nm?.cancel(f.hashCode())
                    evalJs("if (window.onThreatFileDeleted) window.onThreatFileDeleted('${escapeJs(filePath)}');")
                    Toast.makeText(this, "🗑️ Instalador APK infectado eliminado: ${f.name}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun checkAutoConnectVpn(intent: Intent?) {
        if (intent?.getBooleanExtra("EXTRA_AUTO_CONNECT_VPN", false) == true) {
            intent.removeExtra("EXTRA_AUTO_CONNECT_VPN")
            beginVpnConnection("CH")
        }
    }

    private fun startCyberShieldService() {
        try {
            val shieldIntent = Intent(this, SamuVpnService::class.java).apply {
                action = SamuVpnService.ACTION_START_SHIELD
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(shieldIntent)
            } else {
                startService(shieldIntent)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "No se pudo iniciar Cyber-Shield en arranque: ${t.message}")
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 2002) {
            startCyberShieldService()
        }
    }

    override fun onDestroy() {
        SamuVpnService.onProxyFallback = null
        RealtimeDownloadObserver.stopWatching()
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

    fun getDeviceSecurityInfoJson(): JSONObject {
        val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else "2020-01-01"
        return JSONObject().apply {
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
    }

    private fun injectMobileEnvironment() {
        val deviceInfo = getDeviceSecurityInfoJson()
        ioScope.launch {
            try {
                val initAuditReq = JSONObject().apply {
                    put("action", "audit_android_security")
                    put("payload", deviceInfo.toString())
                }
                NativeBridge.dispatchIpc(initAuditReq.toString())
            } catch (t: Throwable) {
                Log.w(TAG, "Error en auditoría inicial ASB: ${t.message}")
            }
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
        SamuVpnService.setTargetCountry(countryCode)
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
            val vpnIntent = Intent(this, SamuVpnService::class.java).apply {
                action = pendingVpnAction
                putExtra(SamuVpnService.EXTRA_PROXY_PORT, SamuSmartProxyServer.DEFAULT_PORT)
                putExtra(SamuVpnService.EXTRA_COUNTRY_CODE, pendingCountry ?: SamuVpnService.activeCountryCode)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(vpnIntent)
            } else {
                startService(vpnIntent)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "No se pudo iniciar SamuVpnService: ${t.message}", t)
        }
        pendingCountry?.let { country ->
            pendingCountry = null
            startTorTunnel(country)
        }
    }

    private fun startTorTunnel(countryCode: String) {
        postVpnEvent("progress", "Estableciendo túnel seguro hacia $countryCode...", null)
        TorManager.startTorForCountry(
            this,
            countryCode,
            onProgress = { msg -> postVpnEvent("progress", msg, null) },
            onResult = { verified, ip ->
                if (verified && ip != null) {
                    postVpnEvent("verified", "IP de salida verificada: $ip (ISP Oculto)", ip)
                } else {
                    postVpnEvent(
                        "timeout",
                        "El circuito seguro en $countryCode está tardando en negociar. Fuga de IP prevenida.",
                        null
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
            // Protección TUN SIEMPRE ACTIVA: Al desconectar la VPN, conmutamos de inmediato
            // al Escudo Zero-Root puro (Mode.SHIELD) para que el filtrado de red TUN
            // y la mitigación de vulnerabilidades nunca se detengan (24/7).
            val shieldIntent = Intent(this, SamuVpnService::class.java).apply {
                action = SamuVpnService.ACTION_START_SHIELD
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(shieldIntent)
            } else {
                startService(shieldIntent)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "No se pudo conmutar SamuVpnService a Escudo TUN: ${t.message}")
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
        } else if (requestCode == uninstallRequestCode) {
            checkPendingUninstalledPackage()
        }
    }

    // ---------------------------------------------------------------- JS bridge

    inner class WebAppInterface {

        fun extractTarget(jsonString: String, key: String): String {
            return try {
                val obj = JSONObject(jsonString)
                var target = obj.optString(key, "")
                if (target.isEmpty() && key == "package_name") {
                    target = obj.optString("package", "")
                }
                if (target.isEmpty()) {
                    val payloadObj = obj.optJSONObject("payload")
                    if (payloadObj != null) {
                        target = payloadObj.optString(key, "").ifEmpty {
                            if (key == "package_name") payloadObj.optString("package", "") else ""
                        }
                    }
                }
                if (target.isEmpty()) {
                    val payload = obj.optString("payload", "")
                    if (payload.startsWith("{")) {
                        try {
                            val inner = JSONObject(payload)
                            target = inner.optString(key, "").ifEmpty {
                                if (key == "package_name") inner.optString("package", "") else ""
                            }
                        } catch (e: Exception) {
                            target = ""
                        }
                    } else if (payload.isNotEmpty() && !payload.startsWith("[")) {
                        target = payload
                    }
                }
                target.trim()
            } catch (e: Exception) {
                ""
            }
        }

        private fun extractFilePath(jsonString: String): String {
            val obj = JSONObject(jsonString)
            var path = obj.optString("path", "").ifEmpty { obj.optString("file_path", "") }
            if (path.isEmpty()) {
                val payload = obj.optString("payload", "")
                if (payload.startsWith("{")) {
                    try {
                        val inner = JSONObject(payload)
                        path = inner.optString("path", "").ifEmpty { inner.optString("file_path", "") }
                    } catch (e: Exception) {
                        path = ""
                    }
                } else {
                    path = payload
                }
            }
            return path.trim()
        }

        @JavascriptInterface
        fun postMessage(jsonString: String): String {
            return try {
                val json = JSONObject(jsonString)
                when (json.optString("action")) {
                    "get_patch_rules", "reaudit_so" -> {
                        val rawPayload = json.optString("payload", "")
                        if (rawPayload.isEmpty() || rawPayload == "null" || json.isNull("payload") || !rawPayload.startsWith("{")) {
                            json.put("payload", getDeviceSecurityInfoJson().toString())
                        }
                        NativeBridge.dispatchIpc(json.toString())
                    }

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
                        SamuVpnService.setTargetCountry(countryCode)
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
                                val isVpnActive = SamuVpnService.isVpnModeActive() || TorManager.activeCountry != null
                                val protectedTunnel = TorManager.isTunnelVerified
                                val ip = if (protectedTunnel) {
                                    TorManager.fetchExternalIpViaSocks5(SamuSmartProxyServer.targetSocksPort)
                                        ?: TorManager.fetchExternalIpViaProxy(TorManager.activeHttpPort)
                                        ?: TorManager.verifiedPublicIp
                                } else {
                                    TorManager.fetchDirectExternalIp()
                                }
                                val resp = JSONObject().apply {
                                    put("action", "check_live_ip")
                                    put("success", ip != null)
                                    put("ip", ip ?: "No disponible")
                                    put("country", if (protectedTunnel) (TorManager.activeCountry ?: "Internacional") else "Local (ISP)")
                                    put("is_protected", protectedTunnel)
                                    put("is_vpn_active", isVpnActive)
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

                    // Escáner profundo de amenazas exclusivo para Android (APKs instalados y en almacenamiento)
                    "start_real_scan", "scan_android_threats" -> {
                        runAndroidDeepThreatScan()
                        JSONObject().apply {
                            put("success", true)
                            put("action", "start_real_scan")
                            put("status", "scanning_started")
                        }.toString()
                    }

                    // Información del programador de escaneo periódico cada 8 días
                    "get_scheduled_scan_info" -> SamuScanScheduler.getSchedulerInfo(this@MainActivity).toString()

                    // Activar o desactivar el escaneo periódico cada 8 días
                    "set_scheduled_scan_enabled" -> {
                        val enabled = extractTarget(jsonString, "enabled").toBooleanStrictOrNull() ?: true
                        SamuScanScheduler.setScheduleEnabled(this@MainActivity, enabled)
                        SamuScanScheduler.getSchedulerInfo(this@MainActivity).toString()
                    }

                    // Forzar escaneo periódico inmediato (actualización de firmas + escaneo profundo)
                    "trigger_scheduled_scan_now" -> {
                        ScheduledScanService.startScan(this@MainActivity)
                        JSONObject().apply {
                            put("success", true)
                            put("message", "Escaneo periódico iniciado de inmediato con actualización previa de firmas.")
                        }.toString()
                    }

                    // Consultar información y estado de la última actualización de firmas
                    "get_signature_update_info" -> SignatureUpdateManager.getLastUpdateInfo(this@MainActivity).toString()

                    // Forzar actualización inmediata de firmas SHA-256 y MD5
                    "update_signatures_now" -> {
                        ioScope.launch {
                            val report = SignatureUpdateManager.updateSignatures(this@MainActivity)
                            withContext(Dispatchers.Main) {
                                evalJs("if (window.onSignaturesUpdated) window.onSignaturesUpdated(${report.totalSignatures}, ${report.signaturesAdded}, '${escapeJs(report.message)}');")
                            }
                        }
                        JSONObject().apply {
                            put("success", true)
                            put("message", "Actualizando base de firmas en segundo plano...")
                        }.toString()
                    }

                    // Cancelar escaneo en curso
                    "cancel_scan" -> {
                        activeScanJob?.cancel()
                        isScanActive.set(false)
                        JSONObject().apply {
                            put("success", true)
                            put("action", "cancel_scan")
                            put("status", "cancelled")
                        }.toString()
                    }

                    // Estado y telemetría en tiempo real de la interfaz TUN de SamuLibre
                    "get_tun_status" -> {
                        SamuVpnService.getTunStats().toString()
                    }

                    // Elimina físicamente un instalador APK infectado de Descargas o almacenamiento
                    "delete_infected_file" -> {
                        val filePath = extractFilePath(jsonString)
                        val success = try {
                            val f = java.io.File(filePath)
                            f.exists() && f.delete()
                        } catch (e: Exception) { false }
                        if (success) {
                            runOnUiThread {
                                evalJs("if (window.onThreatFileDeleted) window.onThreatFileDeleted('${escapeJs(filePath)}');")
                            }
                        }
                        JSONObject().apply {
                            put("success", success)
                            put("deleted", filePath)
                        }.toString()
                    }

                    // Solicita la desinstalación nativa de una aplicación infectada y borrado de rastros
                    "uninstall_package" -> {
                        val pkgName = extractTarget(jsonString, "package_name")
                        if (pkgName.isNotEmpty()) {
                            lastRequestedUninstallPkg = pkgName
                            runOnUiThread {
                                try {
                                    @Suppress("DEPRECATION")
                                    val intent = Intent(Intent.ACTION_DELETE).apply {
                                        data = Uri.fromParts("package", pkgName, null)
                                        putExtra(Intent.EXTRA_RETURN_RESULT, true)
                                    }
                                    startActivityForResult(intent, uninstallRequestCode)
                                } catch (e: Exception) {
                                    Log.w(TAG, "Fallo ACTION_DELETE con resultCode, probando ACTION_UNINSTALL_PACKAGE: ${e.message}")
                                    try {
                                        @Suppress("DEPRECATION")
                                        val fallbackIntent = Intent(Intent.ACTION_UNINSTALL_PACKAGE).apply {
                                            data = Uri.fromParts("package", pkgName, null)
                                            putExtra(Intent.EXTRA_RETURN_RESULT, true)
                                        }
                                        startActivityForResult(fallbackIntent, uninstallRequestCode)
                                    } catch (e2: Exception) {
                                        Log.w(TAG, "Fallo ACTION_UNINSTALL_PACKAGE, probando Settings fallback: ${e2.message}")
                                        try {
                                            val detailsIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                                data = Uri.fromParts("package", pkgName, null)
                                            }
                                            startActivity(detailsIntent)
                                        } catch (e3: Exception) {
                                            Log.e(TAG, "Fallo total intent desinstalación: ${e3.message}")
                                        }
                                    }
                                }
                            }
                        }
                        JSONObject().apply {
                            put("success", true)
                            put("package_name", pkgName)
                        }.toString()
                    }

                    // Borra explícitamente todos los rastros de una app en Android
                    "clean_app_traces" -> {
                        val pkgName = extractTarget(jsonString, "package_name")
                        val count = cleanAppInstallationTraces(pkgName)
                        JSONObject().apply {
                            put("success", true)
                            put("package_name", pkgName)
                            put("traces_cleaned", count)
                        }.toString()
                    }

                    // Abre directamente la pantalla de permisos/ajustes de una app en el sistema Android
                    "open_app_details_settings" -> {
                        val pkgName = extractTarget(jsonString, "package_name")
                        if (pkgName.isNotEmpty()) {
                            lastRequestedUninstallPkg = pkgName
                            runOnUiThread {
                                try {
                                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                        data = Uri.fromParts("package", pkgName, null)
                                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    }
                                    startActivity(intent)
                                } catch (e: Exception) {
                                    Log.e(TAG, "Error abriendo ajustes de app: ${e.message}")
                                }
                            }
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
                    val baseApk = java.io.File(appInfo.sourceDir)
                    val calculatedSha256 = if (baseApk.exists() && baseApk.canRead()) {
                        AndroidThreatDatabase.computeSha256(baseApk)
                    } else ""
                    put("sha256", if (calculatedSha256.isNotEmpty()) calculatedSha256 else JSONObject.NULL)
                })
            }
            return result
        }
    }

    private fun escapeJs(str: String): String {
        return str.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\"", "\\\"")
            .replace("\n", " ")
            .replace("\r", "")
    }

    private fun runAndroidDeepThreatScan() {
        // Cancelar de inmediato cualquier escaneo en curso para evitar ejecuciones concurrentes
        activeScanJob?.cancel()
        activeScanJob = ioScope.launch {
            isScanActive.set(true)
            try {
                // Actualización previa obligatoria de la base de firmas SHA-256 y MD5
                SignatureUpdateManager.updateSignatures(this@MainActivity)

                var scannedCount = 0
                val threatsList = JSONArray()
                val pm = packageManager

                // --- FASE 1: Análisis profundo de aplicaciones instaladas ---
                @Suppress("DEPRECATION")
                val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

                for (pkg in packages) {
                    if (!isScanActive.get() || activeScanJob?.isActive != true) break
                    scannedCount++
                    val appInfo = pkg.applicationInfo ?: continue
                    val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    val isUserApp = !isSystem || isUpdatedSystem

                    val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkg.packageName }

                    withContext(Dispatchers.Main) {
                        evalJs("if (window.onScanProgressUpdate) window.onScanProgressUpdate($scannedCount, '${escapeJs(appName)}', ${threatsList.length()}, false);")
                    }

                    if (!isUserApp) continue

                    val reqPerms = pkg.requestedPermissions ?: emptyArray()
                    val reqFlags = pkg.requestedPermissionsFlags ?: IntArray(0)
                    val grantedPerms = ArrayList<String>()
                    for (i in reqPerms.indices) {
                        if (i < reqFlags.size && (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                            grantedPerms.add(reqPerms[i])
                        }
                    }

                    val hasOverlay = grantedPerms.contains("android.permission.SYSTEM_ALERT_WINDOW") || reqPerms.contains("android.permission.SYSTEM_ALERT_WINDOW")
                    val hasAccessibility = reqPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
                    val hasSms = grantedPerms.any { it.contains("SMS") }
                    val hasInstallPackages = grantedPerms.contains("android.permission.REQUEST_INSTALL_PACKAGES") || reqPerms.contains("android.permission.REQUEST_INSTALL_PACKAGES")

                    val installer = try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                        } else {
                            @Suppress("DEPRECATION")
                            pm.getInstallerPackageName(pkg.packageName)
                        }
                    } catch (e: Exception) { null }

                    val isSideloaded = installer == null || installer == "com.android.packageinstaller" || installer == "com.google.android.packageinstaller"

                    // 0. Detección Heurística de Streaming No Confiable / Proxyware / Rogue Apps (Xuper TV, Magis TV, Tele Latino, etc.)
                    val rogueMatch = AndroidThreatDatabase.checkKnownRoguePackage(pkg.packageName, appName)
                    if (rogueMatch != null && isSideloaded) {
                        threatsList.put(JSONObject().apply {
                            put("type", "APP_INSTALADA")
                            put("severity", "CRITICO")
                            put("category", rogueMatch.category)
                            put("title", rogueMatch.threatName)
                            put("name", appName)
                            put("identifier", pkg.packageName)
                            put("path", appInfo.sourceDir)
                            put("details", rogueMatch.description)
                            put("action", "uninstall")
                        })
                    }

                    // 1. Troyano Bancario Crítico (Accesibilidad abusiva)
                    if (hasAccessibility) {
                        threatsList.put(JSONObject().apply {
                            put("type", "APP_INSTALADA")
                            put("severity", "CRITICO")
                            put("category", "Troyano Bancario / RAT")
                            put("title", "¡Riesgo Crítico de Troyano Bancario!")
                            put("name", appName)
                            put("identifier", pkg.packageName)
                            put("path", appInfo.sourceDir)
                            put("details", "La app tiene activo o solicita el servicio de Accesibilidad (BIND_ACCESSIBILITY_SERVICE). Vector crítico utilizado por TeaBot, Anatsa y SharkBot para robar credenciales bancarias y autorizar transferencias de manera invisible.")
                            put("action", "uninstall")
                        })
                    }

                    // 2. Superposición de Pantalla Sospechosa (Overlay Phishing)
                    if (hasOverlay && isSideloaded && !pkg.packageName.startsWith("org.samulibre.")) {
                        threatsList.put(JSONObject().apply {
                            put("type", "APP_INSTALADA")
                            put("severity", "ALTO")
                            put("category", "Superposición de Pantalla")
                            put("title", "Permiso de Superposición en App Sideloaded")
                            put("name", appName)
                            put("identifier", pkg.packageName)
                            put("path", appInfo.sourceDir)
                            put("details", "Instalada fuera de tiendas oficiales y con permiso SYSTEM_ALERT_WINDOW. Puede falsificar ventanas de inicio de sesión sobre apps de bancos o redes sociales.")
                            put("action", "uninstall")
                        })
                    }

                    // 3. Interceptación Furtiva de Mensajería SMS (Robo de 2FA OTP)
                    if (hasSms && isSideloaded && !pkg.packageName.startsWith("org.samulibre.")) {
                        threatsList.put(JSONObject().apply {
                            put("type", "APP_INSTALADA")
                            put("severity", "ALTO")
                            put("category", "Espía de SMS / 2FA")
                            put("title", "Lectura de SMS en App No Certificada")
                            put("name", appName)
                            put("identifier", pkg.packageName)
                            put("path", appInfo.sourceDir)
                            put("details", "Aplicación externa con permisos para leer mensajes de texto SMS. Posible interceptor de contraseñas bancarias de un solo uso (OTP).")
                            put("action", "uninstall")
                        })
                    }

                    // 4. Dropper de Paquetes Externos
                    if (isSideloaded && hasInstallPackages && !pkg.packageName.startsWith("org.samulibre.")) {
                        threatsList.put(JSONObject().apply {
                            put("type", "APP_INSTALADA")
                            put("severity", "MEDIO")
                            put("category", "Dropper Sospechoso")
                            put("title", "Instalador de APKs Secundario")
                            put("name", appName)
                            put("identifier", pkg.packageName)
                            put("path", appInfo.sourceDir)
                            put("details", "Permiso para forzar instalación de paquetes externos APK silenciosamente.")
                            put("action", "uninstall")
                        })
                    }

                    // 5. Escaneo por base de firmas (SHA-256 / MD5) y motor nativo del archivo APK base
                    try {
                        val apkFile = java.io.File(appInfo.sourceDir)
                        if (apkFile.exists() && apkFile.canRead()) {
                            val signatureMatch = AndroidThreatDatabase.checkFileThreat(apkFile)
                            if (signatureMatch != null) {
                                threatsList.put(JSONObject().apply {
                                    put("type", "APP_INSTALADA")
                                    put("severity", "CRITICO")
                                    put("category", signatureMatch.category)
                                    put("title", signatureMatch.threatName)
                                    put("name", appName)
                                    put("identifier", pkg.packageName)
                                    put("path", appInfo.sourceDir)
                                    put("details", "Firma maliciosa confirmada en base de datos (${signatureMatch.hashType}: ${signatureMatch.hashValue.take(16)}...). ${signatureMatch.description}")
                                    put("action", "uninstall")
                                })
                            } else {
                                val scanRaw = NativeBridge.scanApkFile(apkFile.absolutePath)
                                val scanObj = JSONObject(scanRaw)
                                if (scanObj.optString("status") == "Infected") {
                                    threatsList.put(JSONObject().apply {
                                        put("type", "APP_INSTALADA")
                                        put("severity", "CRITICO")
                                        put("category", "Malware en APK Base")
                                        put("title", scanObj.optString("detection_name", "Malware Android"))
                                        put("name", appName)
                                        put("identifier", pkg.packageName)
                                        put("path", appInfo.sourceDir)
                                        put("details", "Firma maliciosa o payload DEX hostil detectado en el paquete base de la aplicación.")
                                        put("action", "uninstall")
                                    })
                                }
                            }
                        }
                    } catch (e: Exception) {
                        // Ignorar excepciones de lectura en entornos protegidos
                    }
                }

                // --- FASE 2: Rastrear instaladores APK en almacenamiento y Descargas ---
                val canonicalScanDirs = mutableSetOf<String>()
                val scanDirs = mutableListOf<java.io.File>()
                try {
                    android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)?.let {
                        if (it.exists() && canonicalScanDirs.add(it.canonicalPath)) scanDirs.add(it)
                    }
                    val sdcardDownload = java.io.File("/sdcard/Download")
                    if (sdcardDownload.exists() && canonicalScanDirs.add(sdcardDownload.canonicalPath)) scanDirs.add(sdcardDownload)
                    val emulatedDownload = java.io.File("/storage/emulated/0/Download")
                    if (emulatedDownload.exists() && canonicalScanDirs.add(emulatedDownload.canonicalPath)) scanDirs.add(emulatedDownload)
                    val documentsDir = java.io.File("/storage/emulated/0/Documents")
                    if (documentsDir.exists() && canonicalScanDirs.add(documentsDir.canonicalPath)) scanDirs.add(documentsDir)
                } catch (e: Exception) {
                    Log.w(TAG, "Error enumerando directorios de descarga: ${e.message}")
                }

                for (dir in scanDirs) {
                    if (!isScanActive.get() || activeScanJob?.isActive != true) break
                    scanDirectoryForApks(dir, pm, threatsList) { file ->
                        if (!isScanActive.get() || activeScanJob?.isActive != true) return@scanDirectoryForApks
                        scannedCount++
                        withContext(Dispatchers.Main) {
                            evalJs("if (window.onScanProgressUpdate) window.onScanProgressUpdate($scannedCount, '${escapeJs(file.name)}', ${threatsList.length()}, false);")
                        }
                    }
                }

                // --- FASE 3: Enviar reporte consolidado a la interfaz ---
                val finalReport = JSONObject().apply {
                    put("total_scanned", scannedCount)
                    put("threats_count", threatsList.length())
                    put("threats", threatsList)
                    put("timestamp", System.currentTimeMillis())
                }
                SamuScanScheduler.recordScanCompleted(this@MainActivity, threatsList.length())

                withContext(Dispatchers.Main) {
                    evalJs("if (window.onScanProgressUpdate) window.onScanProgressUpdate($scannedCount, 'Análisis finalizado con éxito', ${threatsList.length()}, true);")
                    evalJs("if (window.onAndroidThreatScanFinished) window.onAndroidThreatScanFinished($finalReport);")
                }
            } catch (t: Throwable) {
                if (t !is kotlinx.coroutines.CancellationException) {
                    Log.e(TAG, "Error durante runAndroidDeepThreatScan: ${t.message}", t)
                }
            } finally {
                isScanActive.set(false)
            }
        }
    }

    private suspend fun scanDirectoryForApks(
        dir: java.io.File,
        pm: PackageManager,
        threatsList: JSONArray,
        onFileScanned: suspend (java.io.File) -> Unit
    ) {
        if (!isScanActive.get() || activeScanJob?.isActive != true) return
        if (!dir.exists() || !dir.canRead()) return
        val files = dir.listFiles() ?: return
        for (f in files) {
            if (!isScanActive.get() || activeScanJob?.isActive != true) break
            if (f.isDirectory && !f.name.startsWith(".")) {
                scanDirectoryForApks(f, pm, threatsList, onFileScanned)
            } else if (f.isFile && (f.name.endsWith(".apk", ignoreCase = true) || f.name.endsWith(".xapk", ignoreCase = true))) {
                onFileScanned(f)
                try {
                    val archiveInfo = pm.getPackageArchiveInfo(f.absolutePath, PackageManager.GET_PERMISSIONS)
                    if (archiveInfo == null) {
                        threatsList.put(JSONObject().apply {
                            put("type", "ARCHIVO_APK")
                            put("severity", "ALTO")
                            put("category", "APK Corrupto / Obfuscated")
                            put("title", "Instalador APK Dañado u Ofuscado")
                            put("name", f.name)
                            put("identifier", f.name)
                            put("path", f.absolutePath)
                            put("details", "El archivo APK en Descargas no tiene cabeceras Android válidas o está manipulado con técnicas de evasión anti-análisis.")
                            put("action", "delete_file")
                        })
                    }

                    val apkPkgName = archiveInfo?.packageName ?: ""
                    val rogueMatch = AndroidThreatDatabase.checkKnownRoguePackage(apkPkgName, f.name)
                    if (rogueMatch != null) {
                        threatsList.put(JSONObject().apply {
                            put("type", "ARCHIVO_APK")
                            put("severity", "CRITICO")
                            put("category", rogueMatch.category)
                            put("title", rogueMatch.threatName)
                            put("name", f.name)
                            put("identifier", f.name)
                            put("path", f.absolutePath)
                            put("details", "Instalador no confiable detectado (${rogueMatch.category}). ${rogueMatch.description}")
                            put("action", "delete_file")
                        })
                    } else {
                        val sigMatch = AndroidThreatDatabase.checkFileThreat(f)
                        if (sigMatch != null) {
                            threatsList.put(JSONObject().apply {
                                put("type", "ARCHIVO_APK")
                                put("severity", "CRITICO")
                                put("category", sigMatch.category)
                                put("title", sigMatch.threatName)
                                put("name", f.name)
                                put("identifier", f.name)
                                put("path", f.absolutePath)
                                put("details", "Instalador malicioso confirmado (${sigMatch.hashType}: ${sigMatch.hashValue.take(16)}...). ${sigMatch.description}")
                                put("action", "delete_file")
                            })
                        } else {
                        val scanRaw = NativeBridge.scanApkFile(f.absolutePath)
                        val scanObj = JSONObject(scanRaw)
                        if (scanObj.optString("status") == "Infected") {
                            threatsList.put(JSONObject().apply {
                                put("type", "ARCHIVO_APK")
                                put("severity", "CRITICO")
                                put("category", "Instalador APK Malicioso")
                                put("title", scanObj.optString("detection_name", "Malware Android"))
                                put("name", f.name)
                                put("identifier", f.name)
                                put("path", f.absolutePath)
                                put("details", "Detectado código malicioso en el instalador descargado en disco antes de su instalación.")
                                put("action", "delete_file")
                            })
                        }
                    }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error inspeccionando archivo APK ${f.name}: ${e.message}")
                }
            }
        }
    }

    /**
     * Elimina permanentemente todos los rastros de instalación dejados por una aplicación:
     * - Carpetas en /sdcard/Android/data, /media, /obb
     * - Instaladores .apk / .xapk residuales en descargas o documentos
     * - Directorios ocultos en la raíz del almacenamiento
     */
    fun cleanAppInstallationTraces(pkgName: String): Int {
        if (pkgName.isBlank()) return 0
        var deletedCount = 0
        Log.i(TAG, "Iniciando borrado profundo de rastros para: $pkgName")

        val ext = Environment.getExternalStorageDirectory()
        val targetPaths = listOf(
            File(ext, "Android/data/$pkgName"),
            File(ext, "Android/media/$pkgName"),
            File(ext, "Android/obb/$pkgName"),
            File("/sdcard/Android/data/$pkgName"),
            File("/sdcard/Android/media/$pkgName"),
            File("/sdcard/Android/obb/$pkgName"),
            File("/storage/emulated/0/Android/data/$pkgName"),
            File("/storage/emulated/0/Android/media/$pkgName"),
            File("/storage/emulated/0/Android/obb/$pkgName"),
            File(ext, pkgName),
            File(ext, ".$pkgName")
        )

        for (target in targetPaths) {
            try {
                if (target.exists()) {
                    if (target.isDirectory) {
                        val children = target.listFiles()
                        deletedCount += (children?.size ?: 0) + 1
                        target.deleteRecursively()
                    } else {
                        target.delete()
                        deletedCount++
                    }
                    Log.i(TAG, "Rastro de instalacion eliminado: ${target.absolutePath}")
                }
            } catch (e: Exception) {
                Log.w(TAG, "No se pudo eliminar rastro en ${target.absolutePath}: ${e.message}")
            }
        }

        // Buscar y eliminar instaladores APK droppers residuales en descargas
        val searchDirs = listOf(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            File("/sdcard/Download"),
            File("/sdcard/Downloads"),
            File("/storage/emulated/0/Download")
        )
        val checkedPaths = mutableSetOf<String>()
        for (dir in searchDirs) {
            if (!dir.exists() || !dir.isDirectory) continue
            val allFiles = dir.listFiles() ?: continue

            for (apk in allFiles) {
                if (!apk.isFile) continue
                val name = apk.name.lowercase()
                if (!name.endsWith(".apk") && !name.endsWith(".xapk") && !name.endsWith(".apks")) continue
                if (!checkedPaths.add(apk.absolutePath)) continue
                try {
                    val archiveInfo = packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
                    val archivePkg = archiveInfo?.packageName
                    if (archivePkg == pkgName || apk.name.contains(pkgName, ignoreCase = true)) {
                        if (apk.delete()) {
                            deletedCount++
                            Log.i(TAG, "Instalador residual eliminado de almacenamiento: ${apk.absolutePath}")
                        }
                    }
                } catch (e: Exception) {
                    // ignorar
                }
            }
        }

        Log.i(TAG, "Borrado de rastros completado para $pkgName: $deletedCount elementos eliminados.")
        return deletedCount
    }

    private fun checkPendingUninstalledPackage() {
        val pkg = lastRequestedUninstallPkg ?: return
        try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(pkg, 0)
            // Sigue instalada (el usuario canceló el diálogo del sistema o no desinstaló)
            runOnUiThread {
                evalJs("if (window.onThreatUninstallCancelled) window.onThreatUninstallCancelled('${escapeJs(pkg)}');")
            }
        } catch (e: PackageManager.NameNotFoundException) {
            // Confirmado: La aplicación fue desinstalada con éxito por el sistema
            lastRequestedUninstallPkg = null
            ioScope.launch {
                val cleanedTraces = cleanAppInstallationTraces(pkg)
                runOnUiThread {
                    evalJs("if (window.onThreatPackageRemoved) window.onThreatPackageRemoved('${escapeJs(pkg)}', $cleanedTraces);")
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        checkPendingUninstalledPackage()
        ioScope.launch {
            try {
                RealtimeDownloadObserver.scanAllCandidateDownloads(applicationContext)
            } catch (t: Throwable) {
                Log.w(TAG, "Error en escaneo de descargas en onResume: ${t.message}")
            }
        }
        if (::webView.isInitialized) {
            evalJs("if (window.loadScheduledScanUI) window.loadScheduledScanUI();")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (::webView.isInitialized) {
            webView.evaluateJavascript("if (window.handleAndroidBack) { window.handleAndroidBack(); } else { 'false'; }") { result ->
                val handled = result?.replace("\"", "")?.trim() == "true"
                if (!handled) {
                    if (webView.canGoBack()) {
                        webView.goBack()
                    } else {
                        @Suppress("DEPRECATION")
                        super.onBackPressed()
                    }
                }
            }
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }
}
