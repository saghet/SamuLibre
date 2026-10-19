package org.samulibre.app

import android.content.Context
import android.content.Intent
import android.util.Log
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
    const val HTTP_PROXY_PORT = 49723
    const val SOCKS_PROXY_PORT = 49722

    private var monitorJob: Job? = null
    var activeCountry: String? = null
        private set
    var verifiedPublicIp: String? = null
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
            else -> "{ca}"
        }
    }

    fun startTorForCountry(
        context: Context,
        countryCode: String,
        onStatus: (ready: Boolean, verifiedIp: String?) -> Unit
    ) {
        activeCountry = countryCode
        verifiedPublicIp = null

        val exitNodes = getExitNodesForCountry(countryCode)
        Log.i(TAG, "Configurando circuito Tor móvil para $countryCode con nodos: $exitNodes")

        try {
            val torrcFile = TorService.getTorrc(context)
            val dataDir = File(context.filesDir, "tor_data")
            if (!dataDir.exists()) dataDir.mkdirs()

            val torrcContent = StringBuilder().apply {
                append("HTTPTunnelPort 127.0.0.1:$HTTP_PROXY_PORT\n")
                append("SocksPort 127.0.0.1:$SOCKS_PROXY_PORT\n")
                append("DataDirectory ${dataDir.absolutePath}\n")
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

                // Polling de 12 segundos para detectar la apertura del puerto HTTP
                while (isActive && (System.currentTimeMillis() - startMs) < 12000) {
                    if (isPortOpen("127.0.0.1", HTTP_PROXY_PORT)) {
                        ready = true
                        break
                    }
                    delay(300)
                }

                if (ready) {
                    Log.i(TAG, "Puerto HTTP $HTTP_PROXY_PORT abierto y respondiendo. Verificando IP externa...")
                    val ip = fetchExternalIpViaProxy(HTTP_PROXY_PORT)
                    verifiedPublicIp = ip
                    withContext(Dispatchers.Main) {
                        onStatus(true, ip)
                    }
                } else {
                    Log.w(TAG, "Tor demoró en abrir el puerto, pero el servicio sigue iniciando.")
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
                socket.connect(InetSocketAddress(host, port), 200)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun fetchExternalIpViaProxy(port: Int): String? {
        val testUrls = listOf(
            "https://api.ipify.org?format=json",
            "https://icanhazip.com"
        )
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port))

        for (urlStr in testUrls) {
            try {
                val url = URL(urlStr)
                val conn = (url.openConnection(proxy) as HttpURLConnection).apply {
                    connectTimeout = 3500
                    readTimeout = 3500
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
                // Siguiente proveedor de comprobación
            }
        }
        return null
    }
}
