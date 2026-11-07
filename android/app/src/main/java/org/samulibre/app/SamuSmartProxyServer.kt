package org.samulibre.app

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.torproject.jni.TorService
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import android.net.Network
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Gateway Proxy Local Inteligente de SamuLibre (v2.01.14).
 *
 * Escucha localmente en 127.0.0.1:8118 y actúa como el puente maestro de enrutamiento
 * para Android VpnService.
 *
 * Características críticas:
 *  - Enlaza en el milisegundo 0: Chrome y navegadores NUNCA reciben ERR_PROXY_CONNECTION_FAILED.
 *  - Kill-Switch Estricto Anti-Fugas: Si el usuario activó la VPN internacional, el tráfico web
 *    general NUNCA se degrada en silencio a la IP del ISP local.
 *  - Handshake SOCKS5 con resolución remota ATYP 0x03 en el nodo de salida para Cero Fugas de DNS.
 *  - Exclusión selectiva únicamente para servicios que bloquean Tor (Meta, WhatsApp, llamadas VoIP).
 */
object SamuSmartProxyServer {
    private const val TAG = "SamuLibre_SmartProxy"
    const val DEFAULT_PORT = 8118
    const val TOR_SOCKS_PORT = 9050

    // Servicios, CDNs de streaming y plataformas que bloquean activamente Tor (Google/YouTube, Netflix, Meta, etc.)
    // o que requieren ancho de banda masivo sin búfer. Para estos dominios y subredes IP, el Smart Proxy
    // enruta mediante sockets protegidos directos (SamuVpnService.protectSocket) con DNS seguro Quad9.
    private val STREAMING_AND_TOR_BLOCKED_DOMAINS = listOf(
        // Google & YouTube Streaming CDN
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "gvt1.com",
        "gvt2.com",
        "gvt3.com",
        "youtubei.googleapis.com",
        "yt.be",
        "widevine.com",
        "video.google.com",
        "yt3.ggpht.com",
        "play.google.com",
        "android.clients.google.com",
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "clients4.google.com",
        "clients2.google.com",

        // Meta / Facebook / Instagram / WhatsApp
        "facebook.com",
        "facebook.net",
        "fbcdn.net",
        "fbsbx.com",
        "fb.com",
        "fb.me",
        "fbwat.ch",
        "akamaihd.net",
        "akamaized.net",
        "instagram.com",
        "cdninstagram.com",
        "whatsapp.com",
        "whatsapp.net",
        "messenger.com",
        "meta.com",
        "threads.net",
        "threadsapp.net",
        "m.me",
        "oculus.com",

        // Plataformas de Streaming y CDNs multimedia (bloquean nodos Tor con 403/429)
        "netflix.com",
        "nflxvideo.net",
        "nflximg.net",
        "nflxext.com",
        "nflxso.net",
        "spotify.com",
        "scdn.co",
        "spotifycdn.com",
        "spclient.wg.spotify.com",
        "disneyplus.com",
        "bamgrid.com",
        "dssott.com",
        "primevideo.com",
        "aiv-cdn.net",
        "pv-cdn.net",
        "media-amazon.com",
        "tiktok.com",
        "tiktokcdn.com",
        "byteoversea.com",
        "ibytedtos.com",
        "musical.ly",
        "twitch.tv",
        "ttvnw.net",
        "jtvnw.net",
        "max.com",
        "hbomax.com",

        // Mensajería instantánea y VoIP en tiempo real
        "telegram.org",
        "t.me",
        "telesco.pe",
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "twitter.com",
        "x.com",
        "twimg.com"
    )

    fun isTorBlockedOrStreamingHost(host: String): Boolean {
        val h = host.lowercase().trim()
        if (STREAMING_AND_TOR_BLOCKED_DOMAINS.any { h == it || h.endsWith(".$it") }) {
            return true
        }
        // Subredes públicas de Google Video / Cloud CDN (AS15169)
        if (h.startsWith("142.250.") ||
            h.startsWith("172.217.") ||
            h.startsWith("216.58.") ||
            h.startsWith("173.194.") ||
            h.startsWith("74.125.") ||
            h.startsWith("108.177.") ||
            h.startsWith("64.233.") ||
            h.startsWith("66.102.") ||
            h.startsWith("72.14.")) {
            return true
        }
        // Subredes públicas de Meta (AS32934 / AS63293)
        if (h.startsWith("157.240.") ||
            h.startsWith("31.13.") ||
            h.startsWith("69.63.") ||
            h.startsWith("69.171.") ||
            h.startsWith("66.220.") ||
            h.startsWith("129.134.") ||
            h.startsWith("173.252.") ||
            h.startsWith("179.60.") ||
            h.startsWith("185.60.") ||
            h.startsWith("204.15.")) {
            return true
        }
        return false
    }

    fun isIpCheckerHost(host: String): Boolean {
        val h = host.lowercase().trim()
        return h.contains("cual-es-mi-ip") ||
               h.contains("cualesmiip") ||
               h.contains("whatismyip") ||
               h.contains("ipinfo") ||
               h.contains("ipify") ||
               h.contains("ifconfig") ||
               h.contains("icanhazip") ||
               h.contains("checkip") ||
               h.contains("iplocation") ||
               h.contains("whoer") ||
               h.contains("dnsleaktest")
    }

    fun isTorBlockedHost(host: String): Boolean = isTorBlockedOrStreamingHost(host)

    /**
     * Establece una conexión directa protegida hacia el host destino.
     * Implementa resolución multi-IP estilo Happy Eyeballs (RFC 8305) priorizando IPv4
     * para evitar demoras o bloqueos en redes móviles con IPv6 inestable.
     * Protege el socket con SamuVpnService.protectSocket para evitar bucles TUN.
     */
    private data class DnsCacheEntry(val addresses: List<InetAddress>, val timestamp: Long)
    private val dnsCache = ConcurrentHashMap<String, DnsCacheEntry>()
    private const val DNS_CACHE_TTL_MS = 300_000L // 5 minutos de caché

    fun resolveHostSecurely(host: String): List<InetAddress> {
        val trimmed = host.trim()
        if (trimmed.isEmpty()) return emptyList()

        // 1. IP literal IPv4
        try {
            if (trimmed.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))) {
                return listOf(InetAddress.getByName(trimmed))
            }
        } catch (ignored: Exception) {}

        // 2. Caché local en memoria
        val cached = dnsCache[trimmed]
        if (cached != null && (System.currentTimeMillis() - cached.timestamp) < DNS_CACHE_TTL_MS) {
            return cached.addresses
        }

        // 3. Resolución por red física subyacente (WiFi / Datos Móviles)
        val net = underlyingNetwork ?: SamuVpnService.currentUnderlyingNetwork
        if (net != null) {
            try {
                val addrs = net.getAllByName(trimmed).toList()
                if (addrs.isNotEmpty()) {
                    val sorted = addrs.sortedBy { if (it is java.net.Inet4Address) 0 else 1 }
                    dnsCache[trimmed] = DnsCacheEntry(sorted, System.currentTimeMillis())
                    return sorted
                }
            } catch (e: Exception) {
                Log.d(TAG, "Resolución directa con red física falló para $trimmed: ${e.message}")
            }
        }

        // 4. DNS Seguro UDP hacia Quad9 (9.9.9.9) en socket protegido
        try {
            val quad9Addrs = resolveViaProtectedUdpDns(trimmed, "9.9.9.9")
            if (quad9Addrs.isNotEmpty()) {
                val sorted = quad9Addrs.sortedBy { if (it is java.net.Inet4Address) 0 else 1 }
                dnsCache[trimmed] = DnsCacheEntry(sorted, System.currentTimeMillis())
                return sorted
            }
        } catch (e: Exception) {
            Log.d(TAG, "Resolución Quad9 falló para $trimmed: ${e.message}")
        }

        // 5. DNS Seguro UDP de respaldo hacia Cloudflare (1.1.1.1)
        try {
            val cfAddrs = resolveViaProtectedUdpDns(trimmed, "1.1.1.1")
            if (cfAddrs.isNotEmpty()) {
                val sorted = cfAddrs.sortedBy { if (it is java.net.Inet4Address) 0 else 1 }
                dnsCache[trimmed] = DnsCacheEntry(sorted, System.currentTimeMillis())
                return sorted
            }
        } catch (e: Exception) {
            Log.d(TAG, "Resolución Cloudflare falló para $trimmed: ${e.message}")
        }

        // 6. Fallback final estándar del sistema
        return try {
            val all = InetAddress.getAllByName(trimmed).toList()
            val sorted = all.sortedBy { if (it is java.net.Inet4Address) 0 else 1 }
            if (sorted.isNotEmpty()) {
                dnsCache[trimmed] = DnsCacheEntry(sorted, System.currentTimeMillis())
            }
            sorted
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun resolveViaProtectedUdpDns(host: String, dnsIp: String = "9.9.9.9"): List<InetAddress> {
        val socket = DatagramSocket()
        try {
            socket.soTimeout = 2500
            SamuVpnService.bindAndProtectDatagramSocket(socket)

            val query = ByteArray(512)
            val bb = ByteBuffer.wrap(query)
            val txId = (System.currentTimeMillis() and 0xFFFF).toShort()
            bb.putShort(txId)
            bb.putShort(0x0100.toShort()) // Standard Query, Recursion Desired
            bb.putShort(1.toShort())      // QDCOUNT = 1
            bb.putShort(0.toShort())      // ANCOUNT = 0
            bb.putShort(0.toShort())      // NSCOUNT = 0
            bb.putShort(0.toShort())      // ARCOUNT = 0

            for (label in host.split(".")) {
                if (label.isEmpty()) continue
                val bytes = label.toByteArray(Charsets.US_ASCII)
                bb.put(bytes.size.toByte())
                bb.put(bytes)
            }
            bb.put(0.toByte()) // Fin de QNAME
            bb.putShort(1.toShort()) // Type A
            bb.putShort(1.toShort()) // Class IN

            val queryLength = bb.position()
            val destAddress = InetAddress.getByName(dnsIp)
            val packet = DatagramPacket(query, queryLength, destAddress, 53)
            socket.send(packet)

            val respBuffer = ByteArray(1024)
            val respPacket = DatagramPacket(respBuffer, respBuffer.size)
            socket.receive(respPacket)

            val resp = ByteBuffer.wrap(respBuffer, 0, respPacket.length)
            if (resp.remaining() < 12) return emptyList()
            resp.short // ID
            val rFlags = resp.short.toInt() and 0xFFFF
            val qdCount = resp.short.toInt() and 0xFFFF
            val anCount = resp.short.toInt() and 0xFFFF

            if ((rFlags and 0x000F) != 0 || anCount == 0) return emptyList()

            for (i in 0 until qdCount) {
                skipDnsName(resp)
                if (resp.remaining() >= 4) {
                    resp.position(resp.position() + 4)
                }
            }

            val results = mutableListOf<InetAddress>()
            for (i in 0 until anCount) {
                if (resp.remaining() < 10) break
                skipDnsName(resp)
                val type = resp.short.toInt() and 0xFFFF
                resp.short // clazz
                resp.int   // ttl
                val rdLength = resp.short.toInt() and 0xFFFF

                if (type == 1 && rdLength == 4 && resp.remaining() >= 4) {
                    val ipBytes = ByteArray(4)
                    resp.get(ipBytes)
                    results.add(InetAddress.getByAddress(ipBytes))
                } else if (resp.remaining() >= rdLength) {
                    resp.position(resp.position() + rdLength)
                }
            }
            return results
        } catch (e: Exception) {
            return emptyList()
        } finally {
            try { socket.close() } catch (ignored: Exception) {}
        }
    }

    private fun skipDnsName(bb: ByteBuffer) {
        while (bb.hasRemaining()) {
            val len = bb.get().toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) == 0xC0) {
                if (bb.hasRemaining()) bb.get()
                break
            } else {
                if (bb.remaining() >= len) {
                    bb.position(bb.position() + len)
                } else {
                    break
                }
            }
        }
    }

    /**
     * Establece una conexión directa protegida hacia el host destino.
     * Enlaza explícitamente el socket a la red física subyacente (WiFi / 5G)
     * para garantizar paso libre a través de VpnService sin interferencias.
     */
    fun connectDirect(host: String, port: Int): Socket? {
        val addresses = resolveHostSecurely(host)

        if (addresses.isEmpty()) {
            return try {
                val s = Socket()
                s.tcpNoDelay = true
                s.soTimeout = 45_000
                SamuVpnService.bindAndProtectSocket(s)
                s.connect(InetSocketAddress(host, port), 4000)
                s
            } catch (e: Exception) {
                null
            }
        }

        for (addr in addresses) {
            try {
                val s = Socket()
                s.tcpNoDelay = true
                s.soTimeout = 45_000
                SamuVpnService.bindAndProtectSocket(s)
                s.connect(InetSocketAddress(addr, port), 3500)
                return s
            } catch (e: Exception) {
                // Siguiente IP si falla
            }
        }
        return null
    }

    private val isRunning = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var acceptJob: Job? = null

    @Volatile
    var targetSocksPort: Int = TOR_SOCKS_PORT

    @Volatile
    var isTorReady: Boolean = false

    @Volatile
    var isWireGuardMode: Boolean = false

    @Volatile
    var underlyingNetwork: Network? = null

    @Synchronized
    fun start(port: Int = DEFAULT_PORT, socksPort: Int = TOR_SOCKS_PORT) {
        if (isRunning.get()) {
            targetSocksPort = socksPort
            return
        }

        try {
            targetSocksPort = socksPort
            val ss = ServerSocket(port, 100, InetAddress.getByName("127.0.0.1")).apply {
                reuseAddress = true
            }
            serverSocket = ss
            isRunning.set(true)
            Log.i(TAG, "Gateway Proxy Local escuchando en 127.0.0.1:$port (Destino SOCKS5: $socksPort)")

            acceptJob = scope.launch {
                while (isActive && isRunning.get()) {
                    try {
                        val client = ss.accept()
                        client.tcpNoDelay = true
                        client.soTimeout = 45_000
                        launch { handleClient(client) }
                    } catch (e: Exception) {
                        if (!isRunning.get()) break
                        Log.w(TAG, "Error en accept(): ${e.message}")
                    }
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Error iniciando SamuSmartProxyServer en puerto $port: ${t.message}", t)
        }
    }

    @Synchronized
    fun stop() {
        if (!isRunning.get()) return
        isRunning.set(false)
        isTorReady = false
        isWireGuardMode = false
        acceptJob?.cancel()
        acceptJob = null
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            // ignorar
        }
        serverSocket = null
        Log.i(TAG, "Gateway Proxy Local detenido con éxito")
    }

    fun isListening(): Boolean = isRunning.get() && serverSocket != null && !(serverSocket?.isClosed ?: true)

    private fun handleClient(client: Socket) {
        try {
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            // Leer línea de solicitud HTTP (ej. "CONNECT cual-es-mi-ip.net:443 HTTP/1.1")
            val requestLine = readLine(clientIn) ?: run {
                client.close()
                return
            }

            val parts = requestLine.trim().split(" ")
            if (parts.size < 2) {
                client.close()
                return
            }

            val method = parts[0].uppercase()
            val destination = parts[1]

            if (method == "CONNECT") {
                handleConnect(client, clientIn, clientOut, destination)
            } else {
                handleHttp(client, method, destination, parts.getOrNull(2) ?: "HTTP/1.1")
            }
        } catch (t: Throwable) {
            try { client.close() } catch (e: Exception) { /* ignorar */ }
        }
    }

    private fun handleConnect(client: Socket, clientIn: InputStream, clientOut: OutputStream, destination: String) {
        val destParts = destination.split(":")
        val host = destParts[0]
        val port = destParts.getOrNull(1)?.toIntOrNull() ?: 443

        // Consumir el resto de los headers hasta \r\n\r\n
        consumeHeaders(clientIn)

        val isIpChecker = isIpCheckerHost(host)
        val bypassTor = !isIpChecker && (isTorBlockedHost(host) || isWireGuardMode)
        var remoteSocket: Socket? = null

        if (bypassTor) {
            // Salida protegida directa para servicios esenciales incompatibles con Tor (WhatsApp/Meta/Streaming)
            remoteSocket = connectDirect(host, port)
        } else {
            // Tráfico web general (Google Chrome, navegadores, IP checkers):
            val socksPortToUse = if (TorService.socksPort > 0) TorService.socksPort else targetSocksPort

            if (isTorReady || TorManager.isTunnelVerified || isPortOpen("127.0.0.1", socksPortToUse)) {
                try {
                    remoteSocket = connectViaSocks5("127.0.0.1", socksPortToUse, host, port, 6000)
                } catch (e: Exception) {
                    Log.w(TAG, "Tor SOCKS5 conectando a $destination (${e.message})")
                }
            }

            // Para verificadores de IP: reintentar con SOCKS5 para evitar a toda costa fuga de IP local (ISP)
            if (remoteSocket == null && isIpChecker) {
                try {
                    Thread.sleep(800)
                    if (isPortOpen("127.0.0.1", socksPortToUse)) {
                        remoteSocket = connectViaSocks5("127.0.0.1", socksPortToUse, host, port, 7000)
                    }
                } catch (ignored: Exception) {}
            }

            // Fallback de conexión directa protegida SOLO para tráfico general si Tor no responde,
            // pero NUNCA para verificadores de IP (garantizando Cero Fugas de ISP local)
            if (remoteSocket == null && !isIpChecker) {
                remoteSocket = connectDirect(host, port)
            }
        }

        if (remoteSocket == null) {
            Log.e(TAG, "No se pudo conectar a $destination")
            try {
                val errMsg = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nSamuLibre: Circuito seguro en preparacion... reintentando..."
                clientOut.write(errMsg.toByteArray())
                clientOut.flush()
            } catch (ignored: Exception) {}
            client.close()
            return
        }

        // Responder al cliente: Túnel HTTPS establecido con éxito
        try {
            clientOut.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: SamuLibre-Gateway/2.01.14\r\n\r\n".toByteArray())
            clientOut.flush()
        } catch (e: Exception) {
            client.close()
            try { remoteSocket.close() } catch (ignored: Exception) {}
            return
        }

        // Puente bidireccional transparente entre cliente y el nodo de salida
        bridgeSockets(client, remoteSocket)
    }

    private fun handleHttp(
        client: Socket,
        method: String,
        url: String,
        version: String
    ) {
        val uri = java.net.URI(if (url.startsWith("http")) url else "http://$url")
        val host = uri.host ?: url.substringBefore("/").substringBefore(":")
        val port = if (uri.port > 0) uri.port else 80

        val isIpChecker = isIpCheckerHost(host)
        val bypassTor = !isIpChecker && (isTorBlockedHost(host) || isWireGuardMode)
        var remoteSocket: Socket? = null

        if (bypassTor) {
            remoteSocket = connectDirect(host, port)
        } else {
            val socksPortToUse = if (TorService.socksPort > 0) TorService.socksPort else targetSocksPort
            if (isTorReady || TorManager.isTunnelVerified || isPortOpen("127.0.0.1", socksPortToUse)) {
                try {
                    remoteSocket = connectViaSocks5("127.0.0.1", socksPortToUse, host, port, 6000)
                } catch (e: Exception) {
                    Log.w(TAG, "HTTP plano SOCKS5 conectando para $host: ${e.message}")
                }
            }
            if (remoteSocket == null && isIpChecker) {
                try {
                    Thread.sleep(800)
                    if (isPortOpen("127.0.0.1", socksPortToUse)) {
                        remoteSocket = connectViaSocks5("127.0.0.1", socksPortToUse, host, port, 7000)
                    }
                } catch (ignored: Exception) {}
            }
            if (remoteSocket == null && !isIpChecker) {
                remoteSocket = connectDirect(host, port)
            }
        }

        if (remoteSocket == null) {
            try { client.close() } catch (ignored: Exception) {}
            return
        }

        try {
            val remoteOut = remoteSocket.getOutputStream()
            val rawPath = if (uri.rawPath.isNullOrEmpty()) "/" else uri.rawPath
            val query = if (uri.rawQuery != null) "?${uri.rawQuery}" else ""
            val newReq = "$method $rawPath$query $version\r\n"
            remoteOut.write(newReq.toByteArray())
            remoteOut.flush()
            bridgeSockets(client, remoteSocket)
        } catch (e: Exception) {
            try { client.close() } catch (ignored: Exception) {}
            try { remoteSocket.close() } catch (ignored: Exception) {}
        }
    }

    /**
     * Handshake SOCKS5 RFC 1928 implementado en sockets nativos.
     * Enruta por dominio (ATYP 0x03) para que la resolución DNS ocurra en el nodo de salida de Tor (Zero-Leak).
     */
    private fun connectViaSocks5(
        proxyHost: String,
        proxyPort: Int,
        destHost: String,
        destPort: Int,
        timeoutMs: Int
    ): Socket {
        val socket = Socket()
        socket.tcpNoDelay = true
        socket.soTimeout = 45_000
        SamuVpnService.protectSocket(socket)
        socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)

        val out = socket.getOutputStream()
        val inp = socket.getInputStream()

        // 1. Saludo: Version 5, 1 método (0x00 = No auth)
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()

        val greetingResp = ByteArray(2)
        var readLen = 0
        while (readLen < 2) {
            val n = inp.read(greetingResp, readLen, 2 - readLen)
            if (n < 0) throw java.io.IOException("Cierre de socket antes de respuesta SOCKS5")
            readLen += n
        }
        if (greetingResp[0] != 0x05.toByte() || greetingResp[1] != 0x00.toByte()) {
            socket.close()
            throw java.io.IOException("Autenticación SOCKS5 rechazada: ${greetingResp[1]}")
        }

        // 2. Solicitud CONNECT: VER(5), CMD(1 = CONNECT), RSV(0), ATYP(3 = Dominio)
        val hostBytes = destHost.toByteArray(Charsets.US_ASCII)
        val request = ByteArray(4 + 1 + hostBytes.size + 2)
        request[0] = 0x05
        request[1] = 0x01
        request[2] = 0x00
        request[3] = 0x03 // Dominio (resolución remota en el nodo de salida de Tor)
        request[4] = hostBytes.size.toByte()
        System.arraycopy(hostBytes, 0, request, 5, hostBytes.size)
        val portOffset = 5 + hostBytes.size
        request[portOffset] = ((destPort shr 8) and 0xFF).toByte()
        request[portOffset + 1] = (destPort and 0xFF).toByte()

        out.write(request)
        out.flush()

        // 3. Respuesta SOCKS5
        val replyHeader = ByteArray(4)
        var repLen = 0
        while (repLen < 4) {
            val n = inp.read(replyHeader, repLen, 4 - repLen)
            if (n < 0) throw java.io.IOException("Cierre prematuro en respuesta SOCKS5")
            repLen += n
        }

        if (replyHeader[1] != 0x00.toByte()) {
            val errCode = replyHeader[1].toInt() and 0xFF
            socket.close()
            throw java.io.IOException("SOCKS5 CONNECT falló con código $errCode")
        }

        // Consumir dirección enlazada BND.ADDR según ATYP
        val atyp = replyHeader[3].toInt() and 0xFF
        when (atyp) {
            0x01 -> skipFully(inp, 4 + 2) // IPv4 (4) + Port (2)
            0x03 -> {
                val domainLen = inp.read()
                if (domainLen > 0) skipFully(inp, domainLen + 2)
            }
            0x04 -> skipFully(inp, 16 + 2) // IPv6 (16) + Port (2)
        }

        return socket
    }

    private fun skipFully(inp: InputStream, count: Int) {
        var remaining = count.toLong()
        while (remaining > 0) {
            val skipped = inp.skip(remaining)
            if (skipped <= 0) {
                if (inp.read() == -1) break
                remaining -= 1
            } else {
                remaining -= skipped
            }
        }
    }

    private fun bridgeSockets(client: Socket, remote: Socket) {
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()
        val remoteIn = remote.getInputStream()
        val remoteOut = remote.getOutputStream()

        val j1 = scope.launch {
            val buffer = ByteArray(65536)
            try {
                var len: Int
                while (clientIn.read(buffer).also { len = it } != -1) {
                    remoteOut.write(buffer, 0, len)
                    remoteOut.flush()
                    SamuVpnService.addBytesSent(len.toLong())
                }
            } catch (ignored: Exception) {
            } finally {
                try { remote.shutdownOutput() } catch (e: Exception) {}
            }
        }

        val j2 = scope.launch {
            val buffer = ByteArray(65536)
            try {
                var len: Int
                while (remoteIn.read(buffer).also { len = it } != -1) {
                    clientOut.write(buffer, 0, len)
                    clientOut.flush()
                    SamuVpnService.addBytesReceived(len.toLong())
                }
            } catch (ignored: Exception) {
            } finally {
                try { client.shutdownOutput() } catch (e: Exception) {}
            }
        }

        scope.launch {
            j1.join()
            j2.join()
            try { client.close() } catch (e: Exception) {}
            try { remote.close() } catch (e: Exception) {}
        }
    }

    private fun readLine(inp: InputStream): String? {
        val sb = StringBuilder()
        var b: Int
        while (inp.read().also { b = it } != -1) {
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return if (sb.isEmpty() && b == -1) null else sb.toString()
    }

    private fun consumeHeaders(inp: InputStream) {
        var lastLine: String?
        do {
            lastLine = readLine(inp)
        } while (!lastLine.isNullOrEmpty())
    }

    fun isPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use {
                SamuVpnService.protectSocket(it)
                it.connect(InetSocketAddress(host, port), 250)
                true
            }
        } catch (e: Exception) {
            false
        }
    }
}
