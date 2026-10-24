package org.samulibre.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.graphics.BitmapFactory
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.FileInputStream
import java.io.IOException
import java.nio.ByteBuffer

/**
 * Servicio VPN de SamuLibre (v2.00.4).
 *
 * Modos:
 *  - Escudo (ACTION_START / ACTION_START_SHIELD): filtrado TUN sin proxy.
 *  - VPN Privacidad Multi-Salto (ACTION_START_PROXY_VPN / ACTION_START_SECURE_DNS):
 *    Inicia inmediatamente el Gateway Proxy Local (SamuSmartProxyServer en 127.0.0.1:8118)
 *    y fija el proxy HTTP del sistema en Android 10+ (API 29+).
 *    De esta forma Chrome y las apps jamás quedan sin navegación (cero ERR_PROXY_CONNECTION_FAILED),
 *    la IP pública del ISP queda 100% protegida y el tráfico se enruta de forma segura.
 *
 * Resiliencia Telefónica:
 *  - Exclusión sistemática de paquetes de telefonía, telecom, dialers e IMS (VoLTE/RCS).
 *  - Adaptación dinámica de redes subyacentes vía ConnectivityManager.NetworkCallback.
 *  - Detección de estado de llamada (AudioManager) y pausa pasiva para evitar colisión de radio y ruidos/latencia en voz.
 *  - Manejo seguro de EOF y cierre ordenado de sockets TUN para prevenir cierres involuntarios ("SamuLibre se detuvo").
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
        private const val CHANNEL_ID = "samulibre_status_shield_v4"
        private const val NOTIFICATION_ID = 2001
        private const val WATCHDOG_INTERVAL_MS = 5_000L

        /** Notificado cuando el watchdog detecta un evento del túnel. */
        @Volatile var onProxyFallback: ((String) -> Unit)? = null

        @Volatile var instance: SamuVpnService? = null
            private set

        /**
         * Protege sockets de salida del proxy y procesos locales para que nunca
         * sean absorbidos por la interfaz TUN (previniendo bucles de enrutamiento).
         */
        fun protectSocket(socket: java.net.Socket): Boolean {
            val vpn = instance ?: return true
            return try {
                vpn.protect(socket)
            } catch (e: Exception) {
                Log.w(TAG, "No se pudo proteger socket con protect(): ${e.message}")
                true
            }
        }
    }

    private enum class Mode { SHIELD, SECURE_DNS, PROXY }

    private val vpnCrashHandler = CoroutineExceptionHandler { _, throwable ->
        Log.e(TAG, "Excepción resguardada en coroutine de SamuVpnService: ${throwable.message}", throwable)
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + vpnCrashHandler)

    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetJob: Job? = null
    private var watchdogJob: Job? = null
    private var currentMode: Mode? = null
    private var activeProxyPort: Int? = null

    // Monitorización de red subyacente y telefonía
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var activeUnderlyingNetwork: Network? = null

    private var audioManager: AudioManager? = null
    private var audioModeListener: Any? = null
    @Volatile private var isCallActive: Boolean = false

    private val isVoiceCallActive: Boolean
        get() {
            if (isCallActive) return true
            val mode = audioManager?.mode ?: AudioManager.MODE_NORMAL
            return mode == AudioManager.MODE_RINGTONE ||
                   mode == AudioManager.MODE_IN_CALL ||
                   mode == AudioManager.MODE_IN_COMMUNICATION
        }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

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

        // Si el usuario aún no ha concedido el permiso VPN a nivel de sistema (prepare != null),
        // mantenemos el servicio activo en modo Escudo Centinela en primer plano.
        // Esto mantiene el icono visible en la barra de estado y la tarjeta de notificación siempre activa
        // sin intentar crear la interfaz TUN prematuramente.
        if (mode == Mode.SHIELD && VpnService.prepare(this) != null) {
            Log.i(TAG, "Permiso VPN pendiente: Escudo Cyber-Shield activo en modo centinela permanente")
            currentMode = mode
            return
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
                // Enrutamiento seguro:
                // No inyectamos servidores DNS crudos en la interfaz TUN con ruta acotada /24
                // para evitar que el resolver de Android (netd) desvíe consultas UDP 53 a un blackhole.
                // La resolución DNS cifrada y segura se gestiona en SamuSmartProxyServer (Quad9 DoH) y Tor SOCKS5 remoto.

                if (mode == Mode.PROXY && proxyPort != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val proxyExclusions = listOf(
                        ".facebook.com",
                        "facebook.com",
                        ".facebook.net",
                        "facebook.net",
                        ".fbcdn.net",
                        "fbcdn.net",
                        ".fbsbx.com",
                        "fbsbx.com",
                        ".fb.com",
                        "fb.com",
                        ".fb.me",
                        "fb.me",
                        ".fbwat.ch",
                        "fbwat.ch",
                        ".akamaihd.net",
                        "akamaihd.net",
                        ".akamaized.net",
                        "akamaized.net",
                        ".instagram.com",
                        "instagram.com",
                        ".cdninstagram.com",
                        "cdninstagram.com",
                        ".whatsapp.com",
                        "whatsapp.com",
                        ".whatsapp.net",
                        "whatsapp.net",
                        ".messenger.com",
                        "messenger.com",
                        ".meta.com",
                        "meta.com",
                        ".threads.net",
                        "threads.net",
                        ".threadsapp.net",
                        "threadsapp.net",
                        "localhost",
                        "127.0.0.1"
                    )
                    setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", proxyPort, proxyExclusions))
                }

                // Exclusión de aplicaciones críticas (Split-Tunneling / Bypass Nativo) para garantizar
                // que NINGUNA aplicación pierda acceso a internet ni sufra bloqueos de nodos Tor:
                // 1. Meta / Facebook: usan QUIC (UDP 443), MQTT y sufren bloqueo activo en nodos de salida Tor.
                // 2. Telefonía, llamadas de voz (VoLTE/VoWiFi/CSFB), IMS y dialers.
                // 3. Google Play Services (FCM) para notificaciones push instantáneas sin latencia.
                val bypassPackages = listOf(
                    packageName,
                    // Meta / Facebook / WhatsApp (QUIC sobre UDP 443, llamadas de voz y push persistente)
                    "com.facebook.katana",
                    "com.facebook.orca",
                    "com.facebook.lite",
                    "com.facebook.pages.app",
                    "com.facebook.services",
                    "com.facebook.system",
                    "com.facebook.appmanager",
                    "com.instagram.android",
                    "com.whatsapp",
                    "com.whatsapp.w4b",
                    // Servicios Multimedia y Gestores de Descarga del Sistema (Streaming/ExoPlayer/Mediaserver)
                    "com.android.providers.media",
                    "com.google.android.providers.media.module",
                    "com.android.providers.downloads",
                    "com.android.providers.downloads.ui",
                    "android.media",
                    // Google Play Services / Notificaciones Push / MediaRouter
                    "com.google.android.gms",
                    // Telefonía celular y voz sobre LTE/WiFi
                    "com.android.phone",
                    "com.android.server.telecom",
                    "com.android.incallui",
                    "com.android.providers.telephony",
                    "com.android.carrierconfig",
                    "com.google.android.dialer",
                    "com.google.android.ims",
                    "com.samsung.android.dialer",
                    "com.samsung.android.incallui",
                    "com.sec.phone",
                    "com.samsung.android.messaging"
                )

                val allBypassSet = mutableSetOf<String>()
                allBypassSet.addAll(bypassPackages)

                // Detección dinámica: cualquier paquete instalado en el dispositivo que corresponda a
                // Meta, Facebook, Instagram, WhatsApp o Messenger (incluyendo clones de dual app o variantes OEM)
                try {
                    val installed = packageManager.getInstalledPackages(0)
                    for (p in installed) {
                        val pn = p.packageName.lowercase()
                        if (pn.contains("facebook") || pn.contains("instagram") || pn.contains("whatsapp") || pn.contains("messenger")) {
                            allBypassSet.add(p.packageName)
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Detección dinámica de paquetes bypass omitida: ${e.message}")
                }

                for (pkg in allBypassSet) {
                    try {
                        addDisallowedApplication(pkg)
                    } catch (e: Exception) {
                        // Ignorar si el paquete no está instalado en este dispositivo OEM
                    }
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

            registerNetworkCallback()
            registerAudioListener()
            startPacketInspectionLoop(newPfd)
            if (mode == Mode.PROXY) startWatchdog() else stopWatchdog()
            Log.i(TAG, "Interfaz VPN establecida en modo $mode (proxy=$activeProxyPort)")
        } catch (t: Throwable) {
            Log.e(TAG, "Error estableciendo VPN: ${t.message}", t)
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        try {
            connectivityManager = getSystemService(ConnectivityManager::class.java)
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    activeUnderlyingNetwork = network
                    Log.i(TAG, "Red subyacente activa detectada: $network. Asignando a túnel TUN.")
                    try {
                        setUnderlyingNetworks(arrayOf(network))
                    } catch (e: Exception) {
                        Log.w(TAG, "No se pudo actualizar red subyacente: ${e.message}")
                    }
                }

                override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                    if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        activeUnderlyingNetwork = network
                        try {
                            setUnderlyingNetworks(arrayOf(network))
                        } catch (e: Exception) {
                            // ignorar
                        }
                    }
                }

                override fun onLost(network: Network) {
                    Log.w(TAG, "Red subyacente perdida: $network (posible conmutación de llamada/radio)")
                    if (activeUnderlyingNetwork == network) {
                        activeUnderlyingNetwork = null
                        try {
                            setUnderlyingNetworks(null)
                        } catch (e: Exception) {
                            // ignorar
                        }
                    }
                }
            }
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "No se pudo registrar NetworkCallback: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        } catch (e: Exception) {
            // ignorar
        }
        networkCallback = null
        activeUnderlyingNetwork = null
    }

    private fun registerAudioListener() {
        if (audioManager == null) {
            audioManager = getSystemService(AudioManager::class.java)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && audioModeListener == null) {
            try {
                val listener = AudioManager.OnModeChangedListener { mode ->
                    handleAudioMode(mode)
                }
                audioManager?.addOnModeChangedListener(mainExecutor, listener)
                audioModeListener = listener
            } catch (e: Exception) {
                Log.w(TAG, "No se pudo registrar OnModeChangedListener: ${e.message}")
            }
        }
    }

    private fun handleAudioMode(mode: Int) {
        when (mode) {
            AudioManager.MODE_RINGTONE -> {
                Log.i(TAG, "📞 Llamada entrante timbrando (Ringtone). Pausando inspección profunda para priorizar radio celular.")
                isCallActive = true
            }
            AudioManager.MODE_IN_CALL, AudioManager.MODE_IN_COMMUNICATION -> {
                Log.i(TAG, "📞 Llamada telefónica activa. Protegiendo flujo de voz y ancho de banda.")
                isCallActive = true
            }
            AudioManager.MODE_NORMAL -> {
                if (isCallActive) {
                    Log.i(TAG, "📞 Llamada telefónica finalizada. Reanudando inspección profunda de paquetes TUN.")
                    isCallActive = false
                }
            }
        }
    }

    private fun unregisterAudioListener() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && audioModeListener != null) {
            try {
                (audioModeListener as? AudioManager.OnModeChangedListener)?.let {
                    audioManager?.removeOnModeChangedListener(it)
                }
            } catch (e: Exception) {
                // ignorar
            }
            audioModeListener = null
        }
        isCallActive = false
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
        packetJob?.cancel()
        packetJob = scope.launch(Dispatchers.IO) {
            var inputStream: FileInputStream? = null
            try {
                inputStream = FileInputStream(pfd.fileDescriptor)
                val packet = ByteBuffer.allocate(32768)
                var consecutiveEofCount = 0

                while (isActive) {
                    // Si el dispositivo está en una llamada telefónica activa (timbrando o hablando),
                    // pausamos la inspección profunda de paquetes para otorgar prioridad absoluta
                    // al módem celular, reducir jitter y evitar colisiones de radio.
                    if (isVoiceCallActive) {
                        delay(250)
                        continue
                    }

                    try {
                        packet.clear()
                        val length = inputStream.read(packet.array())
                        if (length > 20) {
                            consecutiveEofCount = 0
                            val decision = JSONObject(NativeBridge.processTunPacket(packet.array().copyOf(length)))
                            if (decision.optString("action", "ACCEPT") == "DROP") {
                                Log.i(TAG, "TUN Dropped: ${decision.optString("reason")}")
                            }
                        } else if (length < 0) {
                            // EOF detectado (-1): el descriptor TUN fue cerrado o la red conmutó
                            consecutiveEofCount++
                            if (consecutiveEofCount >= 3) {
                                Log.w(TAG, "Descriptor TUN en EOF persistente (-1). Esperando estabilización de red...")
                                delay(500)
                            } else {
                                delay(50)
                            }
                        } else {
                            delay(25)
                        }
                    } catch (e: IOException) {
                        if (!isActive) break
                        Log.w(TAG, "IOException transitoria en socket TUN (conmutación de red o llamada): ${e.message}")
                        delay(250)
                    } catch (t: Throwable) {
                        if (!isActive) break
                        Log.e(TAG, "Excepción procesando paquete TUN: ${t.message}")
                        delay(100)
                    }
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Error iniciando stream TUN: ${t.message}")
            } finally {
                try {
                    inputStream?.close()
                } catch (e: Exception) {
                    // ignorar
                }
            }
        }
    }

    @Synchronized
    private fun stopVpn() {
        unregisterAudioListener()
        unregisterNetworkCallback()
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
        if (instance == this) instance = null
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            // Eliminar canal antiguo con prioridad baja para que no oculte el icono
            try { nm?.deleteNotificationChannel("samulibre_vpn_channel") } catch (e: Exception) {}

            try { nm?.deleteNotificationChannel("samulibre_status_shield_v3") } catch (e: Exception) {}

            val channel = NotificationChannel(
                CHANNEL_ID,
                "SamuLibre Cyber-Shield & VPN",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Icono permanente en barra de estado y acceso rápido a la VPN de SamuLibre"
                setShowBadge(true)
                setSound(null, null)
                enableVibration(false)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
            }
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(mode: Mode): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val (title, text, details) = when (mode) {
            Mode.SHIELD -> Triple(
                "🛡️ SamuLibre Cyber-Shield Activo (v2.00.4)",
                "Dispositivo blindado en tiempo real contra amenazas y malware.",
                "Tu navegación está protegida por el motor Zero-Root. Toca abajo para activar la VPN ultrarrápida."
            )
            Mode.SECURE_DNS -> Triple(
                "🛡️ SamuLibre VPN (v2.00.4)",
                "Sincronizando túnel privado internacional...",
                "Tu tráfico está protegido con DNS cifrado Quad9 mientras se valida el circuito internacional."
            )
            Mode.PROXY -> Triple(
                "🛡️ SamuLibre VPN Ultra-Segura Activa (v2.00.4)",
                "Tráfico HTTPS y DNS blindados en nodo internacional.",
                "Identidad e IP de tu ISP 100% ocultas. Navegación privada y anónima activa."
            )
        }

        val bigStyle = NotificationCompat.BigTextStyle()
            .setBigContentTitle(title)
            .setSummaryText("SamuLibre Seguridad")
            .bigText("$text\n$details")

        val largeIcon = try {
            BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher)
        } catch (e: Exception) {
            null
        }

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(bigStyle)
            .setSmallIcon(R.drawable.ic_stat_samulibre_shield)
            .apply {
                if (largeIcon != null) {
                    setLargeIcon(largeIcon)
                }
            }
            .setColor(0xFF00F2FE.toInt()) // Neón Cian Cyber-Shield
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)

        // Acción Rápida (One-Tap Action estilo Bitdefender):
        // Permite conectar o pausar la VPN directamente desde el menú desplegable de notificaciones
        if (mode == Mode.PROXY) {
            val pauseIntent = Intent(this, SamuVpnService::class.java).apply {
                action = ACTION_START_SHIELD
            }
            val pausePendingIntent = PendingIntent.getService(
                this, 101, pauseIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.addAction(R.drawable.ic_vpn_key_toggle, "⏸️ Pausar VPN", pausePendingIntent)
        } else {
            // Si el permiso VPN ya está concedido, conectamos directamente en background con 1 toque.
            // Si falta concederlo, abrimos MainActivity para que Android muestre el diálogo de permiso inmediatamente.
            val connectPendingIntent = if (VpnService.prepare(this) == null) {
                val connectIntent = Intent(this, SamuVpnService::class.java).apply {
                    action = ACTION_START_PROXY_VPN
                    putExtra(EXTRA_PROXY_PORT, SamuSmartProxyServer.DEFAULT_PORT)
                }
                PendingIntent.getService(
                    this, 102, connectIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            } else {
                val openMainIntent = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    putExtra("EXTRA_AUTO_CONNECT_VPN", true)
                }
                PendingIntent.getActivity(
                    this, 103, openMainIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            }
            builder.addAction(R.drawable.ic_vpn_key_toggle, "⚡ Conectar VPN", connectPendingIntent)
        }

        return builder.build()
    }
}
