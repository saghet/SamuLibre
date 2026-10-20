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
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.torproject.jni.TorService
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL

object TorManager {
    private const val TAG = "SamuLibre_TorManager"
    const val HTTP_PROXY_PORT_DEFAULT = 8118
    const val HTTP_PROXY_PORT_FALLBACK = 49723
    const val SOCKS_PROXY_PORT_DEFAULT = 9050

    private var monitorJob: Job? = null
    var activeCountry: String? = null
        private set
    var verifiedPublicIp: String? = null
        private set
    var activeHttpPort: Int = HTTP_PROXY_PORT_DEFAULT
        private set

    private var isReceiverRegistered = false
    private var torStatusReceiver: BroadcastReceiver? = null

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
            else -> "{ca}"
        }
    }

    private fun registerStatusReceiver(context: Context) {
        if (isReceiverRegistered) return
        try {
            torStatusReceiver = object : BroadcastReceiver() {
                override fun onReceive(c: Context?, intent: Intent?) {
                    val status = intent?.getStringExtra(TorService.EXTRA_STATUS)
                    Log.i(TAG, "Tor Broadcast de estado recibido: $status")
                    if (status == TorService.STATUS_ON) {
                        val svcPort = TorService.httpTunnelPort
                        if (svcPort > 0) {
                            activeHttpPort = svcPort
                            Log.i(TAG, "TorService reporta httpTunnelPort activo: $activeHttpPort")
                        }
                    }
                }
            }
            val filter = IntentFilter(TorService.ACTION_STATUS)
            LocalBroadcastManager.getInstance(context).registerReceiver(torStatusReceiver!!, filter)
            context.registerReceiver(torStatusReceiver!!, filter)
            isReceiverRegistered = true
        } catch (t: Throwable) {
            Log.w(TAG, "Aviso registrando BroadcastReceiver de Tor: ${t.message}")
        }
    }

    fun startTorForCountry(
        context: Context,
        countryCode: String,
        onStatus: (ready: Boolean, verifiedIp: String?) -> Unit
    ) {
        activeCountry = countryCode
        verifiedPublicIp = null
        registerStatusReceiver(context)

        val exitNodes = getExitNodesForCountry(countryCode)
        Log.i(TAG, "Iniciando túnel Tor móvil para país $countryCode con nodos: $exitNodes")

        try {
            val torrcFile = TorService.getTorrc(context)
            val dataDir = File(context.filesDir, "tor_data")
            if (!dataDir.exists()) dataDir.mkdirs()

            // Generar torrc limpio compatible con la validación --verify-config de tor-android
            val torrcContent = StringBuilder().apply {
                append("HTTPTunnelPort 127.0.0.1:$HTTP_PROXY_PORT_DEFAULT\n")
                append("SocksPort 127.0.0.1:$SOCKS_PROXY_PORT_DEFAULT\n")
                append("ExitNodes $exitNodes\n")
                append("StrictNodes 0\n")
                append("ClientOnly 1\n")
                append("AvoidDiskWrites 1\n")
            }.toString()

            torrcFile.writeText(torrcContent)
            Log.i(TAG, "Archivo torrc generado en ${torrcFile.absolutePath}")

            val intent = Intent(context, TorService::class.java).apply {
                action = TorService.ACTION_START
            }
            try {
                androidx.core.content.ContextCompat.startForegroundService(context, intent)
            } catch (se: Throwable) {
                try {
                    context.startService(intent)
                } catch (se2: Throwable) {
                    Log.w(TAG, "No fue posible iniciar TorService: ${se2.message}")
                }
            }

            monitorJob?.cancel()
            monitorJob = CoroutineScope(Dispatchers.IO).launch {
                var ready = false
                val startMs = System.currentTimeMillis()
                var detectedPort = HTTP_PROXY_PORT_DEFAULT

                // Sondeo inteligente durante 15s probando 8118, puerto dinámico y 49723
                while (isActive && (System.currentTimeMillis() - startMs) < 15000) {
                    val candidatePort = if (TorService.httpTunnelPort > 0) TorService.httpTunnelPort else HTTP_PROXY_PORT_DEFAULT
                    if (isPortOpen("127.0.0.1", candidatePort)) {
                        ready = true
                        detectedPort = candidatePort
                        break
                    }
                    if (isPortOpen("127.0.0.1", HTTP_PROXY_PORT_FALLBACK)) {
                        ready = true
                        detectedPort = HTTP_PROXY_PORT_FALLBACK
                        break
                    }
                    delay(300)
                }

                activeHttpPort = detectedPort

                if (ready) {
                    Log.i(TAG, "Puerto HTTP $detectedPort abierto y respondiendo. Verificando IP pública externa real...")
                    // Esperar 500ms a que el circuito esté listo para peticiones HTTP
                    delay(500)
                    val ip = fetchExternalIpViaProxy(detectedPort)
                    verifiedPublicIp = ip
                    Log.i(TAG, "Resultado verificación IP pública: $ip")
                    withContext(Dispatchers.Main) {
                        onStatus(true, ip)
                    }
                } else {
                    Log.w(TAG, "Tor tardó en abrir el puerto, usando fallback resiliente.")
                    withContext(Dispatchers.Main) {
                        onStatus(false, null)
                    }
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Error seguro iniciando TorService: ${t.message}", t)
            onStatus(false, null)
        }
    }

    fun stopTor(context: Context) {
        monitorJob?.cancel()
        monitorJob = null
        activeCountry = null
        verifiedPublicIp = null

        try {
            if (isReceiverRegistered && torStatusReceiver != null) {
                try {
                    LocalBroadcastManager.getInstance(context).unregisterReceiver(torStatusReceiver!!)
                    context.unregisterReceiver(torStatusReceiver!!)
                } catch (e: Exception) {
                    // ignorar desregistro
                }
                isReceiverRegistered = false
                torStatusReceiver = null
            }

            val intent = Intent(context, TorService::class.java)
            context.stopService(intent)
            Log.i(TAG, "TorService detenido correctamente.")
        } catch (e: Exception) {
            Log.w(TAG, "Error deteniendo TorService: ${e.message}")
        }
    }

    fun isPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 250)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    fun fetchExternalIpViaProxy(port: Int): String? {
        val testUrls = listOf(
            "https://api.ipify.org?format=json",
            "https://icanhazip.com",
            "https://ifconfig.me/ip"
        )
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port))

        for (urlStr in testUrls) {
            try {
                val url = URL(urlStr)
                val conn = (url.openConnection(proxy) as HttpURLConnection).apply {
                    connectTimeout = 4000
                    readTimeout = 4000
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "SamuLibre-Mobile-Agent/1.99.10")
                }
                if (conn.responseCode == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }.trim()
                    if (body.startsWith("{")) {
                        val json = JSONObject(body)
                        val ip = json.optString("ip")
                        if (ip.isNotEmpty()) return ip
                    } else if (body.isNotEmpty() && body.all { it.isDigit() || it == '.' || it == ':' }) {
                        return body
                    }
                }
            } catch (e: Exception) {
                // Siguiente proveedor de comprobación
            }
        }
        return null
    }

    fun fetchDirectExternalIp(): String? {
        val testUrls = listOf(
            "https://api.ipify.org?format=json",
            "https://icanhazip.com"
        )
        for (urlStr in testUrls) {
            try {
                val url = URL(urlStr)
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    connectTimeout = 3000
                    readTimeout = 3000
                    requestMethod = "GET"
                }
                if (conn.responseCode == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }.trim()
                    if (body.startsWith("{")) {
                        val json = JSONObject(body)
                        val ip = json.optString("ip")
                        if (ip.isNotEmpty()) return ip
                    } else if (body.isNotEmpty() && body.all { it.isDigit() || it == '.' || it == ':' }) {
                        return body
                    }
                }
            } catch (e: Exception) {
                // Siguiente proveedor
            }
        }
        return null
    }
}
