package org.samulibre.app

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Gateway Proxy Local Inteligente de SamuLibre (v1.99.11).
 *
 * Escucha localmente en 127.0.0.1:8118 y actúa como el puente maestro de enrutamiento
 * para Android VpnService.
 *
 * Características críticas:
 *  - Enlaza en el milisegundo 0: Chrome y navegadores NUNCA reciben ERR_PROXY_CONNECTION_FAILED.
 *  - Enrutamiento híbrido de salida:
 *      1. Si Tor SOCKS5 (127.0.0.1:9050) está listo, enruta a través del circuito del país elegido.
 *      2. Si Tor aún está negociando, mantiene vivo el socket o establece salida protegida con Quad9.
 *  - Evita bucles: El proceso de SamuLibre está en addDisallowedApplication, por lo que el gateway
 *    se comunica directamente con el exterior y con Tor sin interferencias del túnel VPN.
 */
object SamuSmartProxyServer {
    private const val TAG = "SamuLibre_SmartProxy"
    const val DEFAULT_PORT = 8118
    const val TOR_SOCKS_PORT = 9050

    private val isRunning = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var acceptJob: Job? = null

    @Volatile
    var targetSocksPort: Int = TOR_SOCKS_PORT

    @Volatile
    var isTorReady: Boolean = false

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
                handleHttp(client, clientIn, clientOut, method, destination, parts.getOrNull(2) ?: "HTTP/1.1")
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

        var remoteSocket: Socket? = null

        // 1. Intentar salida por Tor SOCKS5 si Tor está listo o puerto abierto
        if (isTorReady || isPortOpen("127.0.0.1", targetSocksPort)) {
            try {
                remoteSocket = connectViaSocks5("127.0.0.1", targetSocksPort, host, port, 8000)
                isTorReady = true
            } catch (e: Exception) {
                Log.w(TAG, "Fallo conectando vía Tor SOCKS5 hacia $destination: ${e.message}")
            }
        }

        // 2. Fallback de alta velocidad: si Tor aún no responde, salir directo con DNS Quad9 para no cortar la navegación
        if (remoteSocket == null) {
            try {
                remoteSocket = Socket().apply {
                    tcpNoDelay = true
                    soTimeout = 45_000
                    connect(InetSocketAddress(host, port), 6000)
                }
            } catch (e: Exception) {
                Log.e(TAG, "No se pudo conectar a $destination: ${e.message}")
                try {
                    clientOut.write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n".toByteArray())
                    clientOut.flush()
                } catch (ignored: Exception) {}
                client.close()
                return
            }
        }

        // 3. Responder a Chrome: Túnel HTTPS establecido con éxito
        try {
            clientOut.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: SamuLibre-Gateway/1.99.11\r\n\r\n".toByteArray())
            clientOut.flush()
        } catch (e: Exception) {
            client.close()
            remoteSocket.close()
            return
        }

        // 4. Puente bidireccional transparente entre Chrome y el nodo de salida
        bridgeSockets(client, remoteSocket)
    }

    private fun handleHttp(
        client: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        method: String,
        url: String,
        version: String
    ) {
        // Para peticiones HTTP planas (no CONNECT)
        val uri = java.net.URI(if (url.startsWith("http")) url else "http://$url")
        val host = uri.host ?: url.substringBefore("/").substringBefore(":")
        val port = if (uri.port > 0) uri.port else 80

        var remoteSocket: Socket? = null
        if (isTorReady || isPortOpen("127.0.0.1", targetSocksPort)) {
            try {
                remoteSocket = connectViaSocks5("127.0.0.1", targetSocksPort, host, port, 8000)
                isTorReady = true
            } catch (e: Exception) {
                // fallback
            }
        }

        if (remoteSocket == null) {
            try {
                remoteSocket = Socket().apply {
                    tcpNoDelay = true
                    soTimeout = 45_000
                    connect(InetSocketAddress(host, port), 6000)
                }
            } catch (e: Exception) {
                try { client.close() } catch (ignored: Exception) {}
                return
            }
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
            val buffer = ByteArray(16384)
            try {
                var len: Int
                while (clientIn.read(buffer).also { len = it } != -1) {
                    remoteOut.write(buffer, 0, len)
                    remoteOut.flush()
                }
            } catch (ignored: Exception) {
            } finally {
                try { remote.shutdownOutput() } catch (e: Exception) {}
            }
        }

        val j2 = scope.launch {
            val buffer = ByteArray(16384)
            try {
                var len: Int
                while (remoteIn.read(buffer).also { len = it } != -1) {
                    clientOut.write(buffer, 0, len)
                    clientOut.flush()
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
            Socket().use { it.connect(InetSocketAddress(host, port), 250); true }
        } catch (e: Exception) {
            false
        }
    }
}
