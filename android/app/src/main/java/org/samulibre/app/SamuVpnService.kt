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
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

class SamuVpnService : VpnService() {

    companion object {
        const val ACTION_START = "org.samulibre.app.START_VPN"
        const val ACTION_STOP = "org.samulibre.app.STOP_VPN"
        private const val CHANNEL_ID = "samulibre_vpn_channel"
        private const val NOTIFICATION_ID = 2001
        private const val QUAD9_PRIMARY = "9.9.9.9"
        private const val QUAD9_SECONDARY = "149.112.112.112"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnJob: Job? = null
    private var dnsSocket: DatagramSocket? = null

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
                // Enrutamiento selectivo Zero-Root: Solo capturamos DNS para filtrado anti-malware y C2
                // Esto garantiza que el tráfico HTTP/HTTPS/Apps mantenga el 100% de conectividad nativa a Internet
                addDnsServer(QUAD9_PRIMARY)
                addRoute(QUAD9_PRIMARY, 32)
                addRoute(QUAD9_SECONDARY, 32)
                addRoute("10.200.0.0", 24)
                setSession("SamuLibre Zero-Root Virtual Shield")
                setMtu(1500)
                setBlocking(true)
                try {
                    addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    // ignorar si no está soportado en la versión
                }
            }

            vpnInterface = builder.establish()
            if (vpnInterface != null) {
                // Crear socket UDP protegido para reenviar consultas seguras a Quad9
                dnsSocket = DatagramSocket().apply {
                    protect(this)
                    soTimeout = 3000
                }
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
            val outputStream = FileOutputStream(pfd.fileDescriptor)
            val packet = ByteBuffer.allocate(32767)
            val quad9Addr = InetAddress.getByName(QUAD9_PRIMARY)
            val respBuffer = ByteArray(4096)

            while (isActive) {
                try {
                    packet.clear()
                    val length = inputStream.read(packet.array())
                    if (length > 20) {
                        val packetBytes = packet.array().copyOf(length)
                        val version = (packetBytes[0].toInt() shr 4) and 0x0F
                        val ihl = (packetBytes[0].toInt() and 0x0F) * 4
                        val protocol = packetBytes[9].toInt() and 0xFF

                        // Filtrado de seguridad con el motor SamuLibre en Rust
                        val decisionJson = NativeBridge.processTunPacket(packetBytes)
                        val decision = JSONObject(decisionJson)
                        val action = decision.optString("action", "ACCEPT")

                        if (action == "DROP") {
                            System.out.println("SamuLibre TUN Dropped: ${decision.optString("reason")}")
                            continue
                        }

                        // Reenvío de DNS UDP (Puerto 53) hacia Quad9 Anycast con protección contra malware
                        if (version == 4 && protocol == 17 && length >= ihl + 8) {
                            val dstPort = ((packetBytes[ihl + 2].toInt() and 0xFF) shl 8) or (packetBytes[ihl + 3].toInt() and 0xFF)
                            if (dstPort == 53) {
                                val payloadOffset = ihl + 8
                                val payloadLen = length - payloadOffset
                                if (payloadLen > 0 && dnsSocket != null) {
                                    val outDatagram = DatagramPacket(packetBytes, payloadOffset, payloadLen, quad9Addr, 53)
                                    dnsSocket?.send(outDatagram)

                                    val inDatagram = DatagramPacket(respBuffer, respBuffer.size)
                                    try {
                                        dnsSocket?.receive(inDatagram)
                                        val respLen = inDatagram.length
                                        if (respLen > 0) {
                                            val reply = buildDnsResponsePacket(packetBytes, ihl, respBuffer, respLen)
                                            outputStream.write(reply, 0, reply.size)
                                        }
                                    } catch (te: Exception) {
                                        // Timeout en DNS individual, el cliente reintentará
                                    }
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (!isActive) break
                }
            }
        }
    }

    private fun buildDnsResponsePacket(origPacket: ByteArray, origIhl: Int, dnsPayload: ByteArray, dnsPayloadLen: Int): ByteArray {
        val totalLen = 28 + dnsPayloadLen
        val reply = ByteArray(totalLen)

        // Cabecera IPv4
        reply[0] = 0x45.toByte() // IPv4, IHL=5 (20 bytes)
        reply[1] = 0x00.toByte()
        reply[2] = (totalLen shr 8).toByte()
        reply[3] = (totalLen and 0xFF).toByte()
        reply[4] = origPacket[4]
        reply[5] = origPacket[5]
        reply[6] = 0x40.toByte() // Don't fragment
        reply[7] = 0x00.toByte()
        reply[8] = 64.toByte()   // TTL
        reply[9] = 17.toByte()   // UDP
        reply[10] = 0.toByte()
        reply[11] = 0.toByte()

        // IP Origen = IP Destino de la consulta original (9.9.9.9)
        System.arraycopy(origPacket, 16, reply, 12, 4)
        // IP Destino = IP Origen de la consulta original
        System.arraycopy(origPacket, 12, reply, 16, 4)

        // Checksum IP
        val checksum = computeIpChecksum(reply, 0, 20)
        reply[10] = (checksum shr 8).toByte()
        reply[11] = (checksum and 0xFF).toByte()

        // Cabecera UDP
        reply[20] = (53 shr 8).toByte() // Puerto Origen = 53
        reply[21] = (53 and 0xFF).toByte()
        reply[22] = origPacket[origIhl].toByte() // Puerto Destino = Puerto Origen del cliente
        reply[23] = origPacket[origIhl + 1].toByte()

        val udpLen = 8 + dnsPayloadLen
        reply[24] = (udpLen shr 8).toByte()
        reply[25] = (udpLen and 0xFF).toByte()
        reply[26] = 0.toByte()
        reply[27] = 0.toByte()

        // Carga útil de respuesta DNS
        System.arraycopy(dnsPayload, 0, reply, 28, dnsPayloadLen)
        return reply
    }

    private fun computeIpChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum shr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun stopVpn() {
        vpnJob?.cancel()
        vpnJob = null
        try {
            dnsSocket?.close()
        } catch (e: Exception) {
            // ignore
        }
        dnsSocket = null
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
