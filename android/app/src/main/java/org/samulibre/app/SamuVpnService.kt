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
 * Servicio VPN de SamuLibre (v1.99.10).
 *
 * Modos:
 *  - Escudo (ACTION_START / ACTION_START_SHIELD): filtrado TUN sin proxy.
 *  - Etapa 1 VPN (ACTION_START_SECURE_DNS): túnel con DNS Quad9 y SIN proxy → la navegación nunca se corta
 *    mientras Tor construye el circuito.
 *  - Etapa 2 VPN (ACTION_START_PROXY_VPN): solo se aplica el proxy si el puerto local responde.
 *    Un watchdog revisa el puerto cada 5 s y, si cae, retira el proxy automáticamente
 *    (imposible quedar con ERR_PROXY_CONNECTION_FAILED).
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

        /** Notificado (desde hilo IO) cuando el watchdog retira el proxy por caída del túnel. */
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
                ACTION_START_SECURE_DNS -> establish(Mode.SECURE_DNS, null)
                ACTION_START_PROXY_VPN -> {
                    val port = intent.getIntExtra(EXTRA_PROXY_PORT, TorManager.activeHttpPort)
                    // Guardia: jamás publicar un proxy que no está escuchando.
                    scope.launch {
                        if (TorManager.isPortOpen("127.0.0.1", port)) {
                            establish(Mode.PROXY, port)
                        } else {
                            Log.w(TAG, "Puerto $port cerrado: se mantiene modo DNS seguro sin proxy")
                            establish(Mode.SECURE_DNS, null)
                            onProxyFallback?.invoke("El túnel aún no responde; navegación directa protegida con DNS Quad9.")
                        }
                    }
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
                // Ruta acotada: el tráfico general NO entra al TUN, por lo que nunca se pierde Internet.
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
                    // La propia app (y su proceso Tor) sale directo: evita bucles de enrutamiento.
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

            // Reemplazo sin hueco: se establece la nueva interfaz antes de cerrar la anterior.
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
            var failures = 0
            while (isActive) {
                delay(WATCHDOG_INTERVAL_MS)
                val port = activeProxyPort ?: break
                if (TorManager.isPortOpen("127.0.0.1", port)) {
                    failures = 0
                } else {
                    failures++
                    // Dos fallos seguidos (~10 s) para no reaccionar a micro-cortes.
                    if (failures >= 2) {
                        Log.w(TAG, "Watchdog: puerto $port caído. Retirando proxy para mantener la navegación.")
                        establish(Mode.SECURE_DNS, null)
                        onProxyFallback?.invoke("El túnel se interrumpió. Navegación restaurada automáticamente (DNS Quad9).")
                        break
                    }
                }
            }
        }
    }

    private fun stopWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = null
    }

    private fun startPacketInspectionLoop(pfd: ParcelFileDescriptor) {
        packetJob = scope.launch {
            val inputStream = FileInputStream(pfd.fileDescriptor)
            val packet = ByteBuffer.allocate(32767)
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
        // El usuario activó otra VPN o revocó el permiso.
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
            Mode.SHIELD -> "SamuLibre Shield Activo" to "Filtrando tráfico, puertos de riesgo y exploits ASB (Zero-Root)"
            Mode.SECURE_DNS -> "SamuLibre VPN conectando…" to "Construyendo circuito cifrado. Tu navegación sigue activa con DNS Quad9."
            Mode.PROXY -> "SamuLibre VPN Multi-Salto Activa" to "Tráfico HTTPS enrutado por nodo internacional verificado"
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
