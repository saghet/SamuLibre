package org.samulibre.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.util.Log
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.torproject.jni.TorService
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL

/**
 * Gestor del túnel Tor móvil.
 *
 * Reglas de estabilidad (v1.99.10):
 *  - TorService se inicia SIEMPRE con startService(): la librería tor-android no llama a
 *    startForeground(), por lo que startForegroundService() provoca un ANR/crash en Android 14+.
 *    El servicio en primer plano de la app es SamuVpnService.
 *  - El torrc NO declara puertos: tor-android escribe SOCKSPort/HTTPTunnelPort en torrc-defaults.
 *    Duplicarlos rompe getPortFromGetInfo() y TorService se auto-detiene.
 *  - El túnel solo se declara listo cuando una petición HTTPS real atraviesa el proxy.
 */
@Suppress("DEPRECATION")
object TorManager {
    private const val TAG = "SamuLibre_TorManager"
    const val HTTP_PROXY_PORT_DEFAULT = 8118
    private const val BOOTSTRAP_TIMEOUT_MS = 90_000L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var monitorJob: Job? = null
    private var torStatusReceiver: BroadcastReceiver? = null

    @Volatile var activeCountry: String? = null
        private set
    @Volatile var verifiedPublicIp: String? = null
        private set
    @Volatile var activeHttpPort: Int = HTTP_PROXY_PORT_DEFAULT
        private set
    @Volatile var isTunnelVerified: Boolean = false
        private set

    fun getExitNodesForCountry(countryCode: String): String {
        return when (countryCode.uppercase()) {
            "CH" -> "{ch}"
            "IS" -> "{is},{se},{no}"
            "NL" -> "{nl}"
            "SE" -> "{se}"
            "PA" -> "{pa},{cr},{ca}"
            "CA" -> "{ca}"
            "CO" -> "{co},{pa},{cr}"
            "BR" -> "{br},{cl},{ar}"
            else -> "{ch}"
        }
    }

    private fun registerStatusReceiver(context: Context) {
        if (torStatusReceiver != null) return
        try {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(c: Context?, intent: Intent?) {
                    val status = intent?.getStringExtra(TorService.EXTRA_STATUS)
                    Log.i(TAG, "Estado TorService: $status")
                    if (status == TorService.STATUS_ON && TorService.httpTunnelPort > 0) {
                        activeHttpPort = TorService.httpTunnelPort
                    }
                }
            }
            // Solo LocalBroadcastManager: no requiere flags de exportación en Android 14+.
            LocalBroadcastManager.getInstance(context.applicationContext)
                .registerReceiver(receiver, IntentFilter(TorService.ACTION_STATUS))
            torStatusReceiver = receiver
        } catch (t: Throwable) {
            Log.w(TAG, "No se pudo registrar receptor de estado Tor: ${t.message}")
        }
    }

    /**
     * Arranca Tor hacia el país indicado.
     * [onProgress] se invoca (en Main) con mensajes de progreso.
     * [onResult] se invoca (en Main) una sola vez: verified=true solo si hubo tráfico HTTPS real por el túnel.
     */
    fun startTorForCountry(
        context: Context,
        countryCode: String,
        onProgress: (String) -> Unit,
        onResult: (verified: Boolean, verifiedIp: String?) -> Unit
    ) {
        val appCtx = context.applicationContext
        monitorJob?.cancel()
        activeCountry = countryCode
        verifiedPublicIp = null
        isTunnelVerified = false
        registerStatusReceiver(appCtx)

        monitorJob = scope.launch {
            try {
                val exitNodes = getExitNodesForCountry(countryCode)
                val torrc = buildString {
                    append("ExitNodes $exitNodes\n")
                    append("StrictNodes 0\n")
                    append("ClientOnly 1\n")
                    append("AvoidDiskWrites 1\n")
                }
                TorService.getTorrc(appCtx).writeText(torrc)
                Log.i(TAG, "torrc escrito para $countryCode ($exitNodes)")

                val intent = Intent(appCtx, TorService::class.java).apply { action = TorService.ACTION_START }
                withContext(Dispatchers.Main) {
                    try {
                        appCtx.startService(intent)
                    } catch (t: Throwable) {
                        Log.e(TAG, "No fue posible iniciar TorService: ${t.message}", t)
                    }
                    onProgress("Construyendo circuito cifrado hacia $countryCode...")
                }

                val start = System.currentTimeMillis()
                var lastProgress = 0L
                while (isActive && System.currentTimeMillis() - start < BOOTSTRAP_TIMEOUT_MS) {
                    val port = if (TorService.httpTunnelPort > 0) TorService.httpTunnelPort else HTTP_PROXY_PORT_DEFAULT
                    if (isPortOpen("127.0.0.1", port)) {
                        // El puerto abre antes de que el circuito exista: confirmar con tráfico real.
                        val ip = fetchExternalIpViaProxy(port)
                        if (ip != null) {
                            activeHttpPort = port
                            verifiedPublicIp = ip
                            isTunnelVerified = true
                            Log.i(TAG, "Túnel verificado en puerto $port. IP de salida: $ip")
                            withContext(Dispatchers.Main) { onResult(true, ip) }
                            return@launch
                        }
                    }
                    val elapsed = (System.currentTimeMillis() - start) / 1000
                    if (elapsed - lastProgress >= 8) {
                        lastProgress = elapsed
                        withContext(Dispatchers.Main) {
                            onProgress("Negociando nodos de salida ($elapsed s)... tu navegación sigue activa.")
                        }
                    }
                    delay(1500)
                }
                Log.w(TAG, "Tor no completó el circuito en ${BOOTSTRAP_TIMEOUT_MS / 1000}s")
                withContext(Dispatchers.Main) { onResult(false, null) }
            } catch (t: Throwable) {
                Log.e(TAG, "Error iniciando Tor: ${t.message}", t)
                withContext(Dispatchers.Main) { onResult(false, null) }
            }
        }
    }

    fun stopTor(context: Context) {
        monitorJob?.cancel()
        monitorJob = null
        activeCountry = null
        verifiedPublicIp = null
        isTunnelVerified = false
        try {
            context.applicationContext.stopService(Intent(context.applicationContext, TorService::class.java))
        } catch (t: Throwable) {
            Log.w(TAG, "Error deteniendo TorService: ${t.message}")
        }
    }

    fun isPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use { it.connect(InetSocketAddress(host, port), 300); true }
        } catch (e: Exception) {
            false
        }
    }

    fun fetchExternalIpViaProxy(port: Int): String? =
        fetchIp(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port)), 8000)

    fun fetchDirectExternalIp(): String? = fetchIp(Proxy.NO_PROXY, 4000)

    private fun fetchIp(proxy: Proxy, timeoutMs: Int): String? {
        // Solo HTTPS: HTTPTunnelPort de Tor únicamente acepta túneles CONNECT.
        val urls = listOf("https://api.ipify.org?format=json", "https://icanhazip.com", "https://ifconfig.me/ip")
        for (u in urls) {
            var conn: HttpURLConnection? = null
            try {
                conn = (URL(u).openConnection(proxy) as HttpURLConnection).apply {
                    connectTimeout = timeoutMs
                    readTimeout = timeoutMs
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "SamuLibre-Mobile/1.99.10")
                }
                if (conn.responseCode == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }.trim()
                    val ip = if (body.startsWith("{")) JSONObject(body).optString("ip") else body
                    if (ip.isNotEmpty() && ip.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' }) return ip
                }
            } catch (e: Exception) {
                // probar siguiente proveedor
            } finally {
                conn?.disconnect()
            }
        }
        return null
    }
}
