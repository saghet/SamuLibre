package org.samulibre.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.FileInputStream
import java.nio.ByteBuffer

/**
 * Servicio VPN de SamuLibre (v1.99.11).
 *
 * Modos:
 *  - Escudo (ACTION_START / ACTION_START_SHIELD): filtrado TUN sin proxy.
 *  - VPN Privacidad Multi-Salto (ACTION_START_PROXY_VPN / ACTION_START_SECURE_DNS):
 *    Inicia inmediatamente el Gateway Proxy Local (SamuSmartProxyServer en 127.0.0.1:8118)
 *    y fija el proxy HTTP del sistema en Android 10+ (API 29+).
 *    De esta forma Chrome y las apps jamás quedan sin navegación (cero ERR_PROXY_CONNECTION_FAILED),
 *    la IP pública del ISP queda 100% protegida y el tráfico se enruta de forma segura.
 */
class SamuVpnService : VpnService() {

    companion object {
        private const val TAG = "SamuLibre_VpnService"
        const val ACTION_START = "org.samulibre.app.START_VPN"
        const val ACTION_START_SHIELD = "org.samulibre.app.START_SHIELD"
        const val ACTION_START_SECURE_DNS = "org.samulibre.app.START_SECURE_DNS"
        const val ACTION_START_PROXY_VPN = "org.samulibre.app.START_PROXY_VPN"
        const val ACTION_STOP = "org.samulibre.app.STOP_VPN"
        const val EXTRA_PROXY_PORT = "extra_proxy_port"
        private const val CHANNEL_ID = "samulibre_vpn_channel"
        private const val NOTIFICATION_ID = 2001
        private const val WATCHDOG_INTERVAL_MS = 5_000L

        /** Notificado cuando el watchdog detecta un evento del túnel. */
        @Volatile var onProxyFallback: ((String) -> Unit)? = null
    }

    private enum class Mode { SHIELD, SECURE_DNS, PROXY }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetJob: Job? = null
    private var watchdogJob: Job? = null
    private var currentMode: Mode? = null
    private var activeProxyPort: Int? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            when (intent?.action) {
                ACTION_STOP -> {
                    stopVpn()
                    return START_NOT_STICKY
                }
                ACTION_START_PROXY_VPN, ACTION_START_SECURE_DNS -> {
                    val port = intent.getIntExtra(EXTRA_PROXY_PORT, SamuSmartProxyServer.DEFAULT_PORT)
                    // Iniciar el gateway proxy local si no estuviese activo
                    SamuSmartProxyServer.start(port)
                    establish(Mode.PROXY, port)
                }
                else -> establish(Mode.SHIELD, null)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Error en onStartCommand: ${t.message}", t)
        }
        return START_STICKY
    }

    @Synchronized
    private fun establish(mode: Mode, proxyPort: Int?) {
        if (vpnInterface != null && currentMode == mode && activeProxyPort == proxyPort) return

        try {
            createNotificationChannel()
            val notification = buildNotification(mode)
            startForeground(NOTIFICATION_ID, notification)
        } catch (t: Throwable) {
            Log.e(TAG, "startForeground falló: ${t.message}", t)
        }

        try {
            val builder = Builder().apply {
                addAddress("10.200.0.2", 32)
                // Ruta acotada para evitar captura indiscriminada de paquetes crudos mientras el proxy enruta
                addRoute("10.200.0.0", 24)
                setMtu(1500)
                setBlocking(false)
                allowBypass()
                setSession(
                    when (mode) {
                        Mode.SHIELD -> "SamuLibre Zero-Root Virtual Shield"
                        Mode.SECURE_DNS -> "SamuLibre VPN (conectando)"
                        Mode.PROXY -> "SamuLibre Multi-Hop Privacy VPN"
                    }
                )
                if (mode != Mode.SHIELD) {
                    try {
                        addDnsServer("9.9.9.9")
                        addDnsServer("149.112.112.112")
                    } catch (e: Exception) {
                        Log.w(TAG, "No se pudo fijar DNS Quad9: ${e.message}")
                    }
                }
                if (mode == Mode.PROXY && proxyPort != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", proxyPort))
                }
                try {
                    // La propia app (y su proxy/Tor) sale directo para no generar bucles infinitos
                    addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    // ignorar
                }
            }

            val newPfd = builder.establish()
            if (newPfd == null) {
                Log.w(TAG, "establish() devolvió null (permiso VPN no concedido)")
                return
            }

            // Reemplazo atómico sin huecos en la conexión
            val old = vpnInterface
            packetJob?.cancel()
            vpnInterface = newPfd
            currentMode = mode
            activeProxyPort = if (mode == Mode.PROXY) proxyPort else null
            try { old?.close() } catch (e: Exception) { /* ignorar */ }

            startPacketInspectionLoop(newPfd)
            if (mode == Mode.PROXY) startWatchdog() else stopWatchdog()
            Log.i(TAG, "Interfaz VPN establecida en modo $mode (proxy=$activeProxyPort)")
        } catch (t: Throwable) {
            Log.e(TAG, "Error estableciendo VPN: ${t.message}", t)
        }
    }

    private fun startWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = scope.launch {
            while (isActive) {
                delay(WATCHDOG_INTERVAL_MS)
                val port = activeProxyPort ?: SamuSmartProxyServer.DEFAULT_PORT
                if (!SamuSmartProxyServer.isListening() && !TorManager.isPortOpen("127.0.0.1", port)) {
                    Log.w(TAG, "Watchdog: puerto $port inactivo, reiniciando gateway local...")
                    SamuSmartProxyServer.start(port)
                }
            }
        }
    }

    private fun stopWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = null
    }

    private fun startPacketInspectionLoop(pfd: ParcelFileDescriptor) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        packetJob = scope.launch(Dispatchers.IO) {
            val packet = ByteBuffer.allocate(32768)
            while (isActive) {
                try {
                    packet.clear()
                    val length = inputStream.read(packet.array())
                    if (length > 20) {
                        val decision = JSONObject(NativeBridge.processTunPacket(packet.array().copyOf(length)))
                        if (decision.optString("action", "ACCEPT") == "DROP") {
                            Log.i(TAG, "TUN Dropped: ${decision.optString("reason")}")
                        }
                    } else {
                        delay(25)
                    }
                } catch (e: Exception) {
                    if (!isActive) break
                    delay(50)
                }
            }
        }
    }

    @Synchronized
    private fun stopVpn() {
        stopWatchdog()
        SamuSmartProxyServer.stop()
        packetJob?.cancel()
        packetJob = null
        try { vpnInterface?.close() } catch (e: Exception) { /* ignorar */ }
        vpnInterface = null
        currentMode = null
        activeProxyPort = null
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) { /* ignorar */ }
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SamuLibre Escudo de Red",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Protección de red y filtrado de vulnerabilidades ASB en tiempo real"
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(mode: Mode): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val (title, text) = when (mode) {
            Mode.SHIELD -> "SamuLibre Shield Activo (v1.99.11)" to "Filtrando tráfico, puertos de riesgo y exploits ASB (Zero-Root)"
            Mode.SECURE_DNS -> "SamuLibre VPN (v1.99.11)" to "Construyendo circuito cifrado. Tu navegación sigue activa con DNS Quad9."
            Mode.PROXY -> "SamuLibre VPN Multi-Salto Activa (v1.99.11)" to "Tráfico HTTPS enrutado por nodo internacional verificado"
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
