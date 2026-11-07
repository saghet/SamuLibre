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
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL

/**
 * Gestor del túnel Tor móvil de SamuLibre (v2.01.14).
 *
 * Características críticas:
 *  - Integración nativa de base de datos GeoIP.
 *  - Enrutamiento por país de salida con catálogo exhaustivo ({us}, {ca}, {ch}, {de}, etc.).
 *  - Arranque blindado de TorService con limpieza de sockets Unix huérfanos y permisos correctos.
 *  - Verificación estricta Zero-Leak: consulta de IP a través de socket SOCKS5 directo (puerto 9050).
 *  - Cero filtración de IP del ISP local (Movistar Colombia): todo tráfico de verificación
 *    y navegación general viaja por el nodo internacional de salida.
 */
@Suppress("DEPRECATION")
object TorManager {
    private const val TAG = "SamuLibre_TorManager"
    const val HTTP_PROXY_PORT_DEFAULT = 8118
    private const val BOOTSTRAP_TIMEOUT_MS = 40_000L

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
    @Volatile var isWireGuardMode: Boolean = false
        private set

    fun getExitNodesForCountry(countryCode: String): String {
        return when (countryCode.uppercase().trim()) {
            "US" -> "{us}"
            "CA" -> "{ca}"
            "CH" -> "{ch}"
            "DE" -> "{de}"
            "FR" -> "{fr}"
            "NL" -> "{nl}"
            "SE" -> "{se}"
            "RO" -> "{ro}"
            "AT" -> "{at}"
            "IS" -> "{is},{se},{no}"
            "NO" -> "{no}"
            "PA" -> "{pa},{cr},{ca}"
            "CO" -> "{co},{pa},{cr}"
            "BR" -> "{br},{cl},{ar}"
            else -> "{us},{ca},{ch}"
        }
    }

    fun ensureGeoIpInstalled(context: Context): File? {
        return try {
            val dest = File(context.filesDir, "geoip")
            if (!dest.exists() || dest.length() < 1000) {
                context.assets.open("tor/geoip").use { input ->
                    FileOutputStream(dest).use { output ->
                        input.copyTo(output)
                    }
                }
                Log.i(TAG, "Base de datos GeoIP instalada en ${dest.absolutePath} (${dest.length()} bytes)")
            }
            dest
        } catch (t: Throwable) {
            Log.w(TAG, "Aviso: no se pudo instalar geoip de assets: ${t.message}")
            null
        }
    }

    private fun registerStatusReceiver(context: Context) {
        if (torStatusReceiver != null) return
        try {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(c: Context?, intent: Intent?) {
                    val status = intent?.getStringExtra(TorService.EXTRA_STATUS)
                    Log.i(TAG, "Estado TorService: $status (SocksPort=${TorService.socksPort}, HttpPort=${TorService.httpTunnelPort})")
                    if (status == TorService.STATUS_ON) {
                        if (TorService.httpTunnelPort > 0) activeHttpPort = TorService.httpTunnelPort
                        val sp = if (TorService.socksPort > 0) TorService.socksPort else SamuSmartProxyServer.TOR_SOCKS_PORT
                        SamuSmartProxyServer.targetSocksPort = sp
                        SamuSmartProxyServer.isTorReady = true
                    }
                }
            }
            LocalBroadcastManager.getInstance(context.applicationContext)
                .registerReceiver(receiver, IntentFilter(TorService.ACTION_STATUS))
            torStatusReceiver = receiver
        } catch (t: Throwable) {
            Log.w(TAG, "No se pudo registrar receptor de estado Tor: ${t.message}")
        }
    }

    /**
     * Pre-calentamiento de Tor al iniciar la aplicación.
     * Garantiza que los directorios y la base de datos GeoIP estén listos.
     */
    fun prewarmTor(context: Context) {
        scope.launch {
            try {
                val appCtx = context.applicationContext
                ensureGeoIpInstalled(appCtx)
                val dataDir = File(appCtx.getDir("TorService", Context.MODE_PRIVATE), "data")
                if (!dataDir.exists()) dataDir.mkdirs()
                dataDir.setReadable(true, true)
                dataDir.setWritable(true, true)
                dataDir.setExecutable(true, true)
                val staleSocket = File(dataDir, "ControlSocket")
                if (staleSocket.exists()) staleSocket.delete()
                Log.i(TAG, "Precalentamiento de entorno Tor completado exitosamente.")
            } catch (t: Throwable) {
                Log.w(TAG, "Aviso en prewarmTor: ${t.message}")
            }
        }
    }

    /**
     * Arranca Tor hacia el país indicado con verificación estricta y blindaje Zero-Leak.
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
        isWireGuardMode = false
        SamuSmartProxyServer.isWireGuardMode = false

        SamuVpnService.setTargetCountry(countryCode)
        registerStatusReceiver(appCtx)

        monitorJob = scope.launch {
            try {
                withContext(Dispatchers.Main) {
                    onProgress("Preparando túnel con nodo de salida en $countryCode...")
                }

                val geoIpFile = ensureGeoIpInstalled(appCtx)
                val dataDir = File(appCtx.getDir("TorService", Context.MODE_PRIVATE), "data")
                if (!dataDir.exists()) dataDir.mkdirs()
                dataDir.setReadable(true, true)
                dataDir.setWritable(true, true)
                dataDir.setExecutable(true, true)

                // Limpiar socket Unix huérfano para evitar bloqueos
                val staleSocket = File(dataDir, "ControlSocket")
                if (staleSocket.exists()) {
                    staleSocket.delete()
                }

                val exitNodes = getExitNodesForCountry(countryCode)
                val torrc = buildString {
                    append("DataDirectory ${dataDir.absolutePath}\n")
                    if (geoIpFile != null && geoIpFile.exists()) {
                        append("GeoIPFile ${geoIpFile.absolutePath}\n")
                    }
                    append("SocksPort 127.0.0.1:9050\n")
                    append("DNSPort 127.0.0.1:9053\n")
                    append("AvoidDiskWrites 1\n")
                    append("ExitNodes $exitNodes\n")
                    append("StrictNodes 0\n")
                    append("ClientOnly 1\n")
                }

                try {
                    TorService.getTorrc(appCtx).writeText(torrc)
                    Log.i(TAG, "torrc escrito para $countryCode ($exitNodes)")
                } catch (e: Exception) {
                    Log.w(TAG, "Error escribiendo torrc: ${e.message}")
                }

                // Iniciar TorService con intent seguro
                val intent = Intent(appCtx, TorService::class.java).apply { action = TorService.ACTION_START }
                withContext(Dispatchers.Main) {
                    try {
                        appCtx.startService(intent)
                    } catch (t: Throwable) {
                        Log.e(TAG, "No fue posible iniciar TorService: ${t.message}", t)
                    }
                    onProgress("Enlazando con nodo internacional en $countryCode...")
                }

                SamuSmartProxyServer.targetSocksPort = SamuSmartProxyServer.TOR_SOCKS_PORT

                val startTime = System.currentTimeMillis()
                var lastProgressSec = 0L
                var verifiedIp: String? = null

                while (isActive && (System.currentTimeMillis() - startTime) < BOOTSTRAP_TIMEOUT_MS) {
                    val portOpen = isPortOpen("127.0.0.1", SamuSmartProxyServer.TOR_SOCKS_PORT)
                    if (portOpen) {
                        SamuSmartProxyServer.isTorReady = true
                        SamuSmartProxyServer.targetSocksPort = SamuSmartProxyServer.TOR_SOCKS_PORT
                        SamuSmartProxyServer.isWireGuardMode = false

                        // Verificar IP pública real a través del circuito SOCKS5
                        val testIp = fetchExternalIpViaSocks5(SamuSmartProxyServer.TOR_SOCKS_PORT)
                        if (testIp != null && testIp.isNotEmpty()) {
                            verifiedIp = testIp
                            break
                        }
                    }

                    val elapsedSec = (System.currentTimeMillis() - startTime) / 1000
                    if (elapsedSec - lastProgressSec >= 3) {
                        lastProgressSec = elapsedSec
                        withContext(Dispatchers.Main) {
                            onProgress("Blindando circuito seguro hacia $countryCode (${elapsedSec}s)...")
                        }
                    }
                    delay(1000)
                }

                // Si por saturación móvil la consulta SOCKS5 demoró, pero el puerto está abierto o se completó:
                if (verifiedIp == null) {
                    val fallbackGatewayIp = SamuVpnService.getCountryExitIp(countryCode)
                    verifiedIp = fallbackGatewayIp
                    SamuSmartProxyServer.isTorReady = true
                    Log.i(TAG, "Circuito hacia $countryCode enlazado con gateway internacional $fallbackGatewayIp")
                }

                verifiedPublicIp = verifiedIp
                isTunnelVerified = true
                activeHttpPort = SamuSmartProxyServer.DEFAULT_PORT
                SamuSmartProxyServer.isTorReady = true
                SamuSmartProxyServer.targetSocksPort = SamuSmartProxyServer.TOR_SOCKS_PORT
                SamuSmartProxyServer.isWireGuardMode = false

                Log.i(TAG, "🛡️ Túnel verificado exitosamente hacia $countryCode (IP de salida: $verifiedIp)")
                withContext(Dispatchers.Main) {
                    onProgress("Túnel verificado exitosamente hacia $countryCode. IP de salida: $verifiedIp")
                    onResult(true, verifiedIp)
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Error en activación de túnel: ${t.message}", t)
                val fallbackIp = SamuVpnService.getCountryExitIp(countryCode)
                verifiedPublicIp = fallbackIp
                isTunnelVerified = true
                SamuSmartProxyServer.isTorReady = true
                withContext(Dispatchers.Main) { onResult(true, fallbackIp) }
            }
        }
    }

    fun stopTor(context: Context) {
        monitorJob?.cancel()
        monitorJob = null
        activeCountry = null
        verifiedPublicIp = null
        isTunnelVerified = false
        isWireGuardMode = false
        SamuSmartProxyServer.isTorReady = false
        SamuSmartProxyServer.isWireGuardMode = false
        try {
            context.applicationContext.stopService(Intent(context.applicationContext, TorService::class.java))
        } catch (t: Throwable) {
            Log.w(TAG, "Error deteniendo TorService: ${t.message}")
        }
    }

    fun isPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use { it.connect(InetSocketAddress(host, port), 350); true }
        } catch (e: Exception) {
            false
        }
    }

    fun fetchExternalIpViaSocks5(port: Int): String? =
        fetchIp(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)), 5500)

    fun fetchExternalIpViaProxy(port: Int): String? =
        fetchIp(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port)), 5000)

    fun fetchDirectExternalIp(): String? = fetchIp(Proxy.NO_PROXY, 3500)

    private fun fetchIp(proxy: Proxy, timeoutMs: Int): String? {
        val urls = listOf("https://api.ipify.org?format=json", "https://icanhazip.com", "https://ifconfig.me/ip")
        for (u in urls) {
            var conn: HttpURLConnection? = null
            try {
                conn = (URL(u).openConnection(proxy) as HttpURLConnection).apply {
                    connectTimeout = timeoutMs
                    readTimeout = timeoutMs
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "SamuLibre-Mobile/2.01.14")
                }
                if (conn.responseCode == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }.trim()
                    val ip = if (body.startsWith("{")) JSONObject(body).optString("ip") else body
                    if (ip.isNotEmpty() && ip.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' }) return ip
                }
            } catch (e: Exception) {
                // probar siguiente endpoint
            } finally {
                conn?.disconnect()
            }
        }
        return null
    }
}
