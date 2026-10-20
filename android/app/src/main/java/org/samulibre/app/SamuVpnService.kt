package org.samulibre.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.FileInputStream
import java.nio.ByteBuffer

import android.net.ProxyInfo

class SamuVpnService : VpnService() {

    companion object {
        const val ACTION_START = "org.samulibre.app.START_VPN"
        const val ACTION_START_SHIELD = "org.samulibre.app.START_SHIELD"
        const val ACTION_START_PROXY_VPN = "org.samulibre.app.START_PROXY_VPN"
        const val ACTION_STOP = "org.samulibre.app.STOP_VPN"
        const val EXTRA_PROXY_PORT = "extra_proxy_port"
        private const val CHANNEL_ID = "samulibre_vpn_channel"
        private const val NOTIFICATION_ID = 2001
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnJob: Job? = null
    private var activeProxyPort: Int? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            ACTION_START_PROXY_VPN -> {
                val port = intent.getIntExtra(EXTRA_PROXY_PORT, TorManager.activeHttpPort)
                startVpn(port)
            }
            else -> startVpn(null)
        }
        return START_STICKY
    }

    private fun startVpn(proxyPort: Int? = null) {
        if (vpnInterface != null && activeProxyPort == proxyPort) return

        if (vpnInterface != null) {
            vpnJob?.cancel()
            vpnJob = null
            try {
                vpnInterface?.close()
            } catch (e: Exception) {
                // ignore
            }
            vpnInterface = null
        }

        activeProxyPort = proxyPort
        createNotificationChannel()
        val notification = buildNotification(proxyPort != null)
        startForeground(NOTIFICATION_ID, notification)

        try {
            val builder = Builder().apply {
                addAddress("10.200.0.2", 32)
                addRoute("10.200.0.0", 24)
                if (proxyPort != null) {
                    try {
                        addDnsServer("9.9.9.9")
                        addDnsServer("149.112.112.112")
                    } catch (e: Exception) {
                        // fallback
                    }
                }
                setSession(if (proxyPort != null) "SamuLibre Multi-Hop Privacy VPN" else "SamuLibre Zero-Root Virtual Shield")
                setMtu(1500)
                setBlocking(false)

                // Enrutamiento de proxy HTTP/HTTPS nativo de Android 10+ (API 29+) para cambio real de IP
                if (proxyPort != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    try {
                        val proxyInfo = ProxyInfo.buildDirectProxy("127.0.0.1", proxyPort)
                        setHttpProxy(proxyInfo)
                    } catch (pe: Exception) {
                        pe.printStackTrace()
                    }
                }

                try {
                    addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    // ignorar si no está soportado en la versión
                }
            }

            vpnInterface = builder.establish()
            if (vpnInterface != null) {
                startPacketInspectionLoop(vpnInterface!!)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            stopSelf()
        }
    }

    private fun startPacketInspectionLoop(pfd: ParcelFileDescriptor) {
        vpnJob = CoroutineScope(Dispatchers.IO).launch {
            val inputStream = FileInputStream(pfd.fileDescriptor)
            val packet = ByteBuffer.allocate(32767)

            while (isActive) {
                try {
                    packet.clear()
                    val length = inputStream.read(packet.array())
                    if (length > 20) {
                        val packetBytes = packet.array().copyOf(length)

                        // Filtrado de seguridad con el motor SamuLibre en Rust
                        val decisionJson = NativeBridge.processTunPacket(packetBytes)
                        val decision = JSONObject(decisionJson)
                        val action = decision.optString("action", "ACCEPT")

                        if (action == "DROP") {
                            System.out.println("SamuLibre TUN Dropped: ${decision.optString("reason")}")
                            continue
                        }
                    } else if (length <= 0) {
                        kotlinx.coroutines.delay(10)
                    }
                } catch (e: Exception) {
                    if (!isActive) break
                    kotlinx.coroutines.delay(20)
                }
            }
        }
    }

    private fun stopVpn() {
        vpnJob?.cancel()
        vpnJob = null
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            // ignore
        }
        vpnInterface = null
        activeProxyPort = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
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
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(isProxyVpn: Boolean): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val title = if (isProxyVpn) "SamuLibre VPN Multi-Salto Activa" else "SamuLibre Shield Activo"
        val text = if (isProxyVpn) "Enrutando tráfico cifrado con cambio real de IP internacional" else "Filtrando tráfico, puertos de riesgo y exploits ASB (Zero-Root)"

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
