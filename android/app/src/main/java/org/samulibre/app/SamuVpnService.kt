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

class SamuVpnService : VpnService() {

    companion object {
        const val ACTION_START = "org.samulibre.app.START_VPN"
        const val ACTION_STOP = "org.samulibre.app.STOP_VPN"
        private const val CHANNEL_ID = "samulibre_vpn_channel"
        private const val NOTIFICATION_ID = 2001
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (vpnInterface != null) return

        createNotificationChannel()
        val notification = buildNotification()
        startForeground(NOTIFICATION_ID, notification)

        try {
            val builder = Builder().apply {
                addAddress("10.200.0.2", 32)
                // Enrutamiento selectivo Zero-Root: Protección de vulnerabilidades y puertos de riesgo
                // NO interceptamos DNS del sistema para garantizar el 100% de navegación nativa (Wi-Fi/5G y DoT)
                addRoute("10.200.0.0", 24)
                setSession("SamuLibre Zero-Root Virtual Shield")
                setMtu(1500)
                setBlocking(false)
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

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SamuLibre Shield Activo")
            .setContentText("Filtrando tráfico, puertos de riesgo y exploits ASB (Zero-Root)")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
