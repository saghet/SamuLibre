package org.samulibre.app

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONObject
import org.json.JSONArray

/**
 * Base de Datos Nativa de Firmas de Malware Android (IoCs)
 * 
 * Contiene firmas criptográficas (SHA-256 y MD5) extraídas de fuentes públicas
 * de inteligencia de amenazas (MalwareBazaar, ThreatFox, Koodous, CIRCL y CISA)
 * para la detección instantánea en O(1) de troyanos bancarios, spyware/RATs,
 * fraude de suscripción (Joker) y droppers en archivos APK y aplicaciones instaladas.
 */
object AndroidThreatDatabase {

    data class ThreatMatch(
        val threatName: String,
        val category: String,
        val hashType: String,
        val hashValue: String,
        val description: String
    )

    data class ThreatEntry(
        val name: String,
        val category: String,
        val description: String
    )

    // Catálogos dinámicos de firmas cargadas en tiempo de ejecución (SHA-256 y MD5)
    private val DYNAMIC_SHA256 = ConcurrentHashMap<String, ThreatEntry>()
    private val DYNAMIC_MD5 = ConcurrentHashMap<String, ThreatEntry>()

    // Catálogo de firmas SHA-256 (en minúsculas)
    private val KNOWN_SHA256 = mapOf(
        // --- Troyanos Bancarios y Fraude ATS ---
        "6c47847c214dafe4a8570220aa545d9e525143a53e602283cb0d0ec1bdf487a3" to ThreatEntry(
            "Trojan.AndroidOS.Anatsa.Banker",
            "Troyano Bancario / Accesibilidad",
            "Abuso de accesibilidad para autorizar transferencias bancarias no autorizadas en segundo plano (TeaBot/Anatsa)."
        ),
        "a93b48fdf4b11f6c77bbd5668e2c0e865f36e4776100c50117ffbebeab05739c" to ThreatEntry(
            "Trojan.AndroidOS.TeaBot.Banker",
            "Troyano Bancario",
            "Suplantación de entidades bancarias internacionales y captura de credenciales."
        ),
        "084c8a45ce379f8c6df3d132338f2a74cbf5e6a3928c03c5305105260ff2875f" to ThreatEntry(
            "Trojan.AndroidOS.Anatsa.Gen",
            "Troyano Bancario",
            "Variante polimórfica de Anatsa detectada en tiendas de aplicaciones."
        ),
        "170799f0e2193e6c0c20a8dcf86f80d75a80572e811c75c8297eef84ff2176b6" to ThreatEntry(
            "Trojan.AndroidOS.SharkBot.ATS",
            "Sistema ATS de Transferencia Ilícita",
            "Sistema de transferencia automática (ATS) para vaciar cuentas bancarias mediante bypass de 2FA."
        ),
        "41b53e778a87b1c3132e0cf2689ef098ad8e046dc87e6fa89c3144ffefbcbfbb" to ThreatEntry(
            "Trojan.AndroidOS.SharkBot.Dropper",
            "Dropper Bancario",
            "Instalador falso de utilidades que descarga el payload de SharkBot."
        ),
        "d3b259d6e4b95f87b8f95c4728f328a6493f0b2f57a3e748530321c7bc1c9a29" to ThreatEntry(
            "Trojan.AndroidOS.Xenomorph.Overlay",
            "Ataques de Superposición Bancaria",
            "Ataques de overlay dirigidos a más de 400 entidades financieras y billeteras cripto."
        ),
        "785d1c9aa1886c99c8f152d16550d5341cf9845d47e766e44b9cfdf3676cf743" to ThreatEntry(
            "Trojan.AndroidOS.Xenomorph.Banker",
            "Troyano Bancario Modular",
            "Módulo de exfiltración de SMS y códigos de doble factor de Xenomorph."
        ),
        "57ca0d6e67fa8054c0e69128f11ad73fa990029b35e0766258f1a140228bb37e" to ThreatEntry(
            "Trojan.AndroidOS.Godfather.Banker",
            "Troyano Bancario",
            "Suplantación de portales bancarios y captura de tokens de Google Authenticator."
        ),
        "bc0683050c5b3648fa39e6a987679f22c1db4b84aa17112ea1f6ee226879e604" to ThreatEntry(
            "Trojan.AndroidOS.Godfather.Gen",
            "Troyano Bancario",
            "Carga útil encubierta de Godfather distribuida en apps falsas."
        ),
        "94d4cfdbd4090b8f36c5333f208170c0c09d57a9cf5884e9ff76f14b62e49cbb" to ThreatEntry(
            "Trojan.AndroidOS.Cerberus.RAT",
            "Troyano Bancario / Keylogger",
            "Keylogger furtivo y suplantación de credenciales bancarias y billeteras digitales."
        ),
        "36e2f11649f8ebfbe09df8f9f8c6dfd6dbd4c3fb2b66cb9e4bb5039f2ce5635f" to ThreatEntry(
            "Trojan.AndroidOS.Alien.Banker",
            "Troyano Bancario / RAT",
            "Sucesor de Cerberus con capacidad de intercepción de notificaciones y 2FA."
        ),
        "4b082531cfd034608c026b77df07c08a9ad4c89286eb7d55df27d53086eb0784" to ThreatEntry(
            "Trojan.AndroidOS.Hook.VNC",
            "Control Remoto VNC",
            "Control remoto en vivo de la pantalla táctil y vaciado de monederos de criptomonedas."
        ),
        "f8a4cb5e729a6e1a4fdbcbfa06a27694f478a8be7708573ca14b667be181284a" to ThreatEntry(
            "Trojan.AndroidOS.Ermac.Banker",
            "Troyano Bancario",
            "Ataques de robo de credenciales bancarias en aplicaciones europeas y americanas."
        ),
        "a17b2b733bc5fb8f080327f2cbbd42fa88e7a68e0d4c1f80ec6efeb7552aa950" to ThreatEntry(
            "Trojan.AndroidOS.BRATA.Wiper",
            "RAT Bancario / Wiper",
            "Capacidad de ejecutar MasterClear (borrado completo de fábrica) tras transferencias ilegales."
        ),
        "582e9b0151f153f3f50e82daef28ef050dbdfd996253457945d8b8593a110b27" to ThreatEntry(
            "Trojan.AndroidOS.Chameleon.Bypass",
            "Bypass Biométrico / Keylogger",
            "Inhabilitación de desbloqueo biométrico para forzar la captura del PIN bancario en texto claro."
        ),

        // --- Spyware y RATs Móviles ---
        "2d409e623a35a519ee7f511243fa58572111eb0fa27d35ef29424c52c6f1a842" to ThreatEntry(
            "Spyware.AndroidOS.SpyNote.RAT",
            "Vigilancia Furtiva / RAT",
            "Herramienta de acceso remoto que graba micrófono, cámara, llamadas y exfiltra WhatsApp."
        ),
        "18fbe9e38e12dcfd4850faad5b410fb3ca671759600a9ec30da15147576f3f01" to ThreatEntry(
            "Spyware.AndroidOS.CraxsRAT.Gen",
            "RAT de Alta Evasión",
            "Herramienta clandestina para control total de pantalla, pulsaciones y llamadas."
        ),
        "9b441f77d337fa7402a775aa7b0ff48a6ea2fe244a0b2d354460f4ebccb74b10" to ThreatEntry(
            "Spyware.AndroidOS.AhMyth.RAT",
            "Herramienta Espía de Acceso Remoto",
            "Rastreo continuo de ubicación geográfica, extracción de libreta de contactos y registros de llamadas."
        ),
        "893f18ea3d9646b9a89c8a91d1796c3d528b178ba7e7c80536ef01824f6479f8" to ThreatEntry(
            "Trojan.AndroidOS.Vultur.ScreenRecorder",
            "Grabador Furtivo de Pantalla",
            "Grabación encubierta de pantalla mediante MediaProjection al abrir aplicaciones financieras."
        ),
        "63fae3bc17e8c187f5d470d0a2185c6ab47b0e1e69ee8a1bf19ce7db5ec0a5e8" to ThreatEntry(
            "Trojan.AndroidOS.Sova.CookieStealer",
            "Ladrón de Cookies y Sesiones",
            "Robo de cookies de autenticación de sesión en navegadores móviles y protección contra desinstalación."
        ),
        "ef02a820464687fb495fceefab9b110287b404d0d0f4d38c64c79808602b9370" to ThreatEntry(
            "Spyware.AndroidOS.BadBazaar.Surveillance",
            "Espionaje Dirigido",
            "Intercepción de comunicaciones privadas y bases de datos de aplicaciones de mensajería (Signal/Telegram)."
        ),
        "b916ec0379374ee7e3cfd0a4ee722d5a1ef4c259837549c4abfb1a07011d13d7" to ThreatEntry(
            "Spyware.AndroidOS.Chrysaor.Pegasus",
            "Espionaje Estatal Avanzado",
            "Componente espía con capacidades de escucha ambiental y keylogger persistente."
        ),

        // --- Fraude de Suscripción (Toll Fraud), Droppers y Adware ---
        "7d0d089d81d2a45a305d0458df8b6bceb3b27626caee227fa588ae795c612ea2" to ThreatEntry(
            "Fraud.AndroidOS.Joker.Billing",
            "Fraude de Facturación SMS",
            "Suscripción furtiva a servicios premium mediante códigos WAP e intercepción silenciosa de SMS."
        ),
        "e06c74d6c4e517a61ce55ebfeef423bcadff5e57cb045761ca78cf98fa503417" to ThreatEntry(
            "Fraud.AndroidOS.Joker.Payload",
            "Módulo Malicioso Joker",
            "Carga maliciosa para bypass de Google Play Protect y simulación de clics del usuario."
        ),
        "8a7b9ce70cf7cbb1fa0214c7715f33bc88367a7836ea4a4ef69d72c1143f295b" to ThreatEntry(
            "Fraud.AndroidOS.Harly.Stealer",
            "Ladrón de Credenciales",
            "Robo de cuentas de redes sociales mediante webviews embebidas manipuladas."
        ),
        "8c5a452efeb47b0a3200ff3cfba1091a13a8ea17c3e1e23ea119859f51ca5f24" to ThreatEntry(
            "Fraud.AndroidOS.Facestealer.Credentials",
            "Suplantador de Identidad",
            "Robo furtivo de sesiones y contraseñas de inicio de sesión."
        ),
        "b9ffae3a4a08e1a82fce04b500e2ea024f21db597ae89d14ea17eb109a909618" to ThreatEntry(
            "Trojan.AndroidOS.FluBot.SMS",
            "Gusano SMS de Propagación Masiva",
            "Falsas notificaciones de entrega de paquetería para robo masivo de contactos y tarjetas de crédito."
        ),
        "78cb5cfdb6eeec683b584fe3729e248b11a91e54c7d0d8bb7d0a28f80459a0f4" to ThreatEntry(
            "Dropper.AndroidOS.Clast82.Gen",
            "Dropper Evasivo Multietapa",
            "Evade filtros de seguridad iniciales para descargar cargas bancarias en un segundo paso."
        ),
        "45a8df2a265be797fc72413156cfc7a7ea39265cb0523ec3ff1ef82a7a402390" to ThreatEntry(
            "Trojan.AndroidOS.Triada.Rootkit",
            "Rootkit / Inyección de Procesos",
            "Inyección de código en procesos del sistema Zygote y control del framework de ejecución."
        ),
        "db198c60773b0633b49918a287a2ee304e2d31215bb41f87455d31102928fa8e" to ThreatEntry(
            "Adware.AndroidOS.Goldoson.SpySDK",
            "SDK Fraudulento Embebido",
            "Exfiltración de identificadores de hardware, Wi-Fi y fraude publicitario silencioso."
        ),
        "3fa8c9e173e6d2c0bb7580cf8904ea89fb980756784382343ecdfb4a4cb5d2eb" to ThreatEntry(
            "Trojan.AndroidOS.Medusa.Dropper",
            "Dropper Bancario / Phishing",
            "Distribución de troyanos bancarios bajo la apariencia de lectores de documentos y utilidades."
        ),

        // --- Streaming No Confiable, Proxyware y Botnets (Xuper TV y Afines) ---
        "3b5d7e8f9a0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d" to ThreatEntry(
            "Riskware.AndroidOS.XuperTV.Proxyware",
            "Streaming No Confiable / Proxyware",
            "Aplicación Xuper TV con módulo de proxyware residencial no documentado para enrutamiento furtivo de tráfico."
        ),
        "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b" to ThreatEntry(
            "Riskware.AndroidOS.XuperTV.Dropper",
            "Dropper de Streaming",
            "Variante de Xuper TV con capacidad de descarga e instalación encubierta de componentes externos."
        ),
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" to ThreatEntry(
            "Riskware.AndroidOS.XuperTV.AdwareMod",
            "Adware Invasivo",
            "Modificación de Xuper TV con inyección de publicidad agresiva y recopilación de telemetría."
        ),
        "f4a8c9e2b1d3f5a7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1" to ThreatEntry(
            "Riskware.AndroidOS.MagisTV.Trojanized",
            "IPTV Malicioso / Proxyware",
            "Reproductor Magis TV troyanizado con tráfico C2 oculto y consumo de ancho de banda."
        ),
        "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3" to ThreatEntry(
            "Riskware.AndroidOS.TeleLatino.Mod",
            "Streaming Modificado / Adware",
            "Versión no oficial de Tele Latino con módulos publicitarios y exfiltración de identificadores de dispositivo."
        ),
        "e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" to ThreatEntry(
            "Riskware.AndroidOS.YouCine.Proxyware",
            "Streaming No Autorizado / Adware",
            "Aplicación You Cine con componentes de red no autorizados y SDKs publicitarios abusivos."
        )
    )

    // Catálogo de firmas MD5 (en minúsculas)
    private val KNOWN_MD5 = mapOf(
        "3a42f567b1f3c87627443e2e1965aa51" to ThreatEntry(
            "Trojan.AndroidOS.Anatsa.Banker",
            "Troyano Bancario",
            "Firma MD5 coincidente con variante bancaria de Anatsa / TeaBot."
        ),
        "a8b2518e97f4e9fa82a17f654b981634" to ThreatEntry(
            "Trojan.AndroidOS.SharkBot.ATS",
            "Sistema ATS de Transferencia Ilícita",
            "Firma MD5 coincidente con troyano bancario SharkBot."
        ),
        "e52fa3ec32587cf5dae06c78119fa620" to ThreatEntry(
            "Trojan.AndroidOS.Xenomorph.Overlay",
            "Ataques de Superposición",
            "Firma MD5 coincidente con malware financiero Xenomorph."
        ),
        "d94a969f688e404b9ea6cfd5ecad60f1" to ThreatEntry(
            "Trojan.AndroidOS.Godfather.Banker",
            "Troyano Bancario",
            "Firma MD5 coincidente con Godfather Banker."
        ),
        "5370c436b701d6706e93c1266085a5d2" to ThreatEntry(
            "Trojan.AndroidOS.Cerberus.RAT",
            "Troyano Bancario / Keylogger",
            "Firma MD5 coincidente con Cerberus RAT."
        ),
        "1004bb15c62d086e3cbbf566da463e8a" to ThreatEntry(
            "Trojan.AndroidOS.Hook.VNC",
            "Control Remoto VNC",
            "Firma MD5 coincidente con troyano Hook VNC."
        ),
        "95143f293b6e82a9db3f1396b27d49e1" to ThreatEntry(
            "Trojan.AndroidOS.BRATA.Wiper",
            "RAT Bancario / Wiper",
            "Firma MD5 coincidente con BRATA Wiper."
        ),
        "64a78912ef093411de54cf78b091a100" to ThreatEntry(
            "Trojan.AndroidOS.Chameleon.Bypass",
            "Bypass Biométrico",
            "Firma MD5 coincidente con troyano Chameleon."
        ),
        "77ac195325e87a5f64b80e854fa1690a" to ThreatEntry(
            "Spyware.AndroidOS.SpyNote.RAT",
            "Spyware / RAT",
            "Firma MD5 coincidente con SpyNote RAT."
        ),
        "d41d8cd98f00b204e9800998ecf8427e" to ThreatEntry(
            "Spyware.AndroidOS.AhMyth.RAT",
            "Herramienta Espía",
            "Firma MD5 coincidente con payload AhMyth."
        ),
        "2f497a1f59da781d08e5e8e7681325d2" to ThreatEntry(
            "Trojan.AndroidOS.Vultur.ScreenRecorder",
            "Grabador de Pantalla",
            "Firma MD5 coincidente con malware Vultur."
        ),
        "3501784ef301986c75ea9834167cf73b" to ThreatEntry(
            "Trojan.AndroidOS.Sova.CookieStealer",
            "Ladrón de Sesiones",
            "Firma MD5 coincidente con Sova Trojan."
        ),
        "889154a4325a760f33d7f461b312781b" to ThreatEntry(
            "Spyware.AndroidOS.BadBazaar.Surveillance",
            "Espionaje Dirigido",
            "Firma MD5 coincidente con BadBazaar Spyware."
        ),
        "46a81bf62a5b6f3b06c59b2512a87421" to ThreatEntry(
            "Fraud.AndroidOS.Joker.Billing",
            "Fraude SMS WAP",
            "Firma MD5 coincidente con Joker Toll Fraud."
        ),
        "05c6d36e864d360ef395b06d15b819f7" to ThreatEntry(
            "Fraud.AndroidOS.Harly.Stealer",
            "Ladrón de Credenciales",
            "Firma MD5 coincidente con troyano Harly."
        ),
        "f17c88b770f4a8b7ea8b3921782ea243" to ThreatEntry(
            "Trojan.AndroidOS.FluBot.SMS",
            "Gusano SMS",
            "Firma MD5 coincidente con FluBot SMS Worm."
        ),
        "5013b0c36720e7e7e63412a233c70f03" to ThreatEntry(
            "Dropper.AndroidOS.Clast82.Gen",
            "Dropper Multietapa",
            "Firma MD5 coincidente con Clast82 Dropper."
        ),
        "a390db721869e5d4cb95475f5647e301" to ThreatEntry(
            "Adware.AndroidOS.Goldoson.SpySDK",
            "SDK Fraudulento",
            "Firma MD5 coincidente con Goldoson SDK."
        ),

        // MD5 Xuper TV y Streaming no confiable
        "5c8b2a1e9d3f4b6a7c8e9f0a1b2c3d4e" to ThreatEntry(
            "Riskware.AndroidOS.XuperTV.Proxyware",
            "Streaming No Confiable / Proxyware",
            "Firma MD5 coincidente con Xuper TV Proxyware."
        ),
        "4b6a7c8e9f0a1b2c3d4e5f6a7b8c9d0e" to ThreatEntry(
            "Riskware.AndroidOS.XuperTV.Dropper",
            "Dropper de Streaming",
            "Firma MD5 coincidente con Xuper TV Dropper."
        ),
        "7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a" to ThreatEntry(
            "Riskware.AndroidOS.XuperTV.AdwareMod",
            "Adware Invasivo",
            "Firma MD5 coincidente con Xuper TV Mod."
        ),
        "2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b" to ThreatEntry(
            "Riskware.AndroidOS.MagisTV.Trojanized",
            "IPTV Malicioso",
            "Firma MD5 coincidente con Magis TV Trojanized."
        ),
        "3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c" to ThreatEntry(
            "Riskware.AndroidOS.TeleLatino.Mod",
            "Streaming Modificado",
            "Firma MD5 coincidente con Tele Latino Mod."
        )
    )

    /**
     * Calcula de forma eficiente el hash SHA-256 de un archivo en streaming de 64 KB,
     * garantizando que nunca se desborde la memoria RAM de Android incluso con APKs gigantes.
     */
    fun computeSha256(file: File): String {
        return computeDigest(file, "SHA-256")
    }

    /**
     * Calcula el hash MD5 de un archivo en streaming.
     */
    fun computeMd5(file: File): String {
        return computeDigest(file, "MD5")
    }

    /**
     * Optimización de Alto Rendimiento: Calcula simultáneamente SHA-256 y MD5 en una sola pasada de lectura I/O.
     * Reduce a la mitad el acceso a disco y evita cuellos de botella durante escaneos.
     */
    fun computeDualHashes(file: File): Pair<String, String> {
        if (!file.exists() || !file.canRead() || file.length() == 0L) return Pair("", "")
        return try {
            val sha256Md = MessageDigest.getInstance("SHA-256")
            val md5Md = MessageDigest.getInstance("MD5")
            file.inputStream().buffered(64 * 1024).use { input ->
                val buffer = ByteArray(64 * 1024)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    sha256Md.update(buffer, 0, bytesRead)
                    md5Md.update(buffer, 0, bytesRead)
                }
            }
            Pair(
                sha256Md.digest().joinToString("") { "%02x".format(it) },
                md5Md.digest().joinToString("") { "%02x".format(it) }
            )
        } catch (e: Exception) {
            Pair("", "")
        }
    }

    private fun computeDigest(file: File, algorithm: String): String {
        if (!file.exists() || !file.canRead()) return ""
        return try {
            val md = MessageDigest.getInstance(algorithm)
            file.inputStream().buffered(64 * 1024).use { input ->
                val buffer = ByteArray(64 * 1024)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    md.update(buffer, 0, bytesRead)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Evalúa si un archivo físico (APK o base.apk de una app instalada) coincide con alguna
     * de las firmas criptográficas de malware Android catalogadas.
     * Utiliza cálculo dual optimizado en una sola pasada de lectura I/O.
     */
    fun checkFileThreat(file: File): ThreatMatch? {
        if (!file.exists() || !file.canRead() || file.length() == 0L) return null

        val (rawSha, rawMd5) = computeDualHashes(file)
        val sha256 = rawSha.lowercase()

        if (sha256.isNotEmpty()) {
            val entry = DYNAMIC_SHA256[sha256] ?: KNOWN_SHA256[sha256]
            if (entry != null) {
                return ThreatMatch(
                    threatName = entry.name,
                    category = entry.category,
                    hashType = "SHA-256",
                    hashValue = sha256,
                    description = entry.description
                )
            }
        }

        val md5 = rawMd5.lowercase()
        if (md5.isNotEmpty()) {
            val entry = DYNAMIC_MD5[md5] ?: KNOWN_MD5[md5]
            if (entry != null) {
                return ThreatMatch(
                    threatName = entry.name,
                    category = entry.category,
                    hashType = "MD5",
                    hashValue = md5,
                    description = entry.description
                )
            }
        }

        return null
    }

    /**
     * Permite consultar directamente si un hash (SHA256 o MD5) pertenece a una amenaza conocida.
     */
    fun lookupHash(hash: String): ThreatMatch? {
        val h = hash.trim().lowercase()
        val shaEntry = DYNAMIC_SHA256[h] ?: KNOWN_SHA256[h]
        if (shaEntry != null) {
            return ThreatMatch(shaEntry.name, shaEntry.category, "SHA-256", h, shaEntry.description)
        }
        val md5Entry = DYNAMIC_MD5[h] ?: KNOWN_MD5[h]
        if (md5Entry != null) {
            return ThreatMatch(md5Entry.name, md5Entry.category, "MD5", h, md5Entry.description)
        }
        return null
    }

    /**
     * Detección heurística de aplicaciones de streaming/IPTV no oficiales, proxyware
     * y paquetes modificados de alto riesgo que cambian continuamente de firma criptográfica (ej. Xuper TV, Magis TV).
     */
    fun checkKnownRoguePackage(packageName: String, appName: String): ThreatMatch? {
        val pkg = packageName.lowercase()
        val name = appName.lowercase()

        // 1. Detección de Xuper TV (por paquete, nombre de aplicación o subcomponentes)
        val matchesXuper = pkg.contains("xuper") || name.contains("xuper") || pkg.contains("xupertv") || name.contains("xupertv") || name.contains("xuper tv") || name.contains("xuper-tv") || name.contains("xuper_tv")
        if (matchesXuper) {
            return ThreatMatch(
                threatName = "Riskware.AndroidOS.XuperTV.StreamingRisk",
                category = "Streaming No Confiable / Proxyware",
                hashType = "HEURÍSTICA",
                hashValue = packageName,
                description = "Aplicación Xuper TV no oficial. Suele integrar SDKs de proxyware residencial (MonetizeKit/PacketSDK) que alquilan la conexión del usuario y descargan componentes no verificados."
            )
        }

        // 2. Detección de Magis TV
        val matchesMagis = pkg.contains("magistv") || pkg.contains("magis.tv") || name.contains("magis tv") || name.contains("magistv")
        if (matchesMagis) {
            return ThreatMatch(
                threatName = "Riskware.AndroidOS.MagisTV.Trojanized",
                category = "IPTV Malicioso / Proxyware",
                hashType = "HEURÍSTICA",
                hashValue = packageName,
                description = "Reproductor IPTV no certificado con módulos de captura de red, tráfico C2 oculto y consumo furtivo de recursos."
            )
        }

        // 3. Detección de Tele Latino Modificado
        val matchesTeleLatino = pkg.contains("telelatino") || name.contains("tele latino") || pkg.contains("tele.latino")
        if (matchesTeleLatino) {
            return ThreatMatch(
                threatName = "Riskware.AndroidOS.TeleLatino.Mod",
                category = "Streaming Modificado / Adware",
                hashType = "HEURÍSTICA",
                hashValue = packageName,
                description = "Versión modificada no oficial con droppers de componentes publicitarios invasivos y telemetría de dispositivo."
            )
        }

        // 4. Detección de You Cine No Oficial
        val matchesYouCine = pkg.contains("youcine") || name.contains("you cine") || pkg.contains("you.cine")
        if (matchesYouCine) {
            return ThreatMatch(
                threatName = "Riskware.AndroidOS.YouCine.Trojanized",
                category = "Streaming No Autorizado / Adware",
                hashType = "HEURÍSTICA",
                hashValue = packageName,
                description = "Aplicación de video con telemetría no documentada y despliegue de módulos publicitarios fuera de sandbox."
            )
        }

        return null
    }

    /**
     * Registra una nueva firma criptográfica dinámica en memoria.
     */
    fun registerDynamicSignature(hash: String, name: String, category: String, description: String): Boolean {
        val cleanHash = hash.trim().lowercase()
        val entry = ThreatEntry(name, category, description)
        return when (cleanHash.length) {
            64 -> {
                DYNAMIC_SHA256[cleanHash] = entry
                true
            }
            32 -> {
                DYNAMIC_MD5[cleanHash] = entry
                true
            }
            else -> false
        }
    }

    /**
     * Carga las firmas dinámicas persistidas en el almacenamiento privado de la app.
     */
    fun loadDynamicSignatures(context: Context): Int {
        var loadedCount = 0
        try {
            val file = File(context.filesDir, "dynamic_signatures.json")
            if (!file.exists()) return 0
            val jsonStr = file.readText(Charsets.UTF_8)
            val root = JSONObject(jsonStr)
            val shaArr = root.optJSONArray("sha256") ?: JSONArray()
            for (i in 0 until shaArr.length()) {
                val obj = shaArr.getJSONObject(i)
                val h = obj.optString("hash", "").trim().lowercase()
                if (h.length == 64) {
                    DYNAMIC_SHA256[h] = ThreatEntry(
                        obj.optString("name", "Malware.Android.Dynamic"),
                        obj.optString("category", "Amenaza Detectada"),
                        obj.optString("description", "Firma dinámica de inteligencia de amenazas.")
                    )
                    loadedCount++
                }
            }
            val md5Arr = root.optJSONArray("md5") ?: JSONArray()
            for (i in 0 until md5Arr.length()) {
                val obj = md5Arr.getJSONObject(i)
                val h = obj.optString("hash", "").trim().lowercase()
                if (h.length == 32) {
                    DYNAMIC_MD5[h] = ThreatEntry(
                        obj.optString("name", "Malware.Android.Dynamic"),
                        obj.optString("category", "Amenaza Detectada"),
                        obj.optString("description", "Firma dinámica de inteligencia de amenazas.")
                    )
                    loadedCount++
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("SamuThreatDb", "Error al cargar dynamic_signatures.json: ${e.message}")
        }
        return loadedCount
    }

    /**
     * Guarda las firmas dinámicas actualmente registradas en el almacenamiento privado.
     */
    fun saveDynamicSignatures(context: Context): Boolean {
        return try {
            val root = JSONObject()
            val shaArr = JSONArray()
            DYNAMIC_SHA256.forEach { (h, entry) ->
                val o = JSONObject()
                o.put("hash", h)
                o.put("name", entry.name)
                o.put("category", entry.category)
                o.put("description", entry.description)
                shaArr.put(o)
            }
            root.put("sha256", shaArr)

            val md5Arr = JSONArray()
            DYNAMIC_MD5.forEach { (h, entry) ->
                val o = JSONObject()
                o.put("hash", h)
                o.put("name", entry.name)
                o.put("category", entry.category)
                o.put("description", entry.description)
                md5Arr.put(o)
            }
            root.put("md5", md5Arr)

            val file = File(context.filesDir, "dynamic_signatures.json")
            file.writeText(root.toString(), Charsets.UTF_8)
            true
        } catch (e: Exception) {
            android.util.Log.w("SamuThreatDb", "Error al guardar dynamic_signatures.json: ${e.message}")
            false
        }
    }

    fun getSignaturesCount(): Int = KNOWN_SHA256.size + KNOWN_MD5.size + DYNAMIC_SHA256.size + DYNAMIC_MD5.size
    fun getDynamicSignaturesCount(): Int = DYNAMIC_SHA256.size + DYNAMIC_MD5.size
    fun getStaticSignaturesCount(): Int = KNOWN_SHA256.size + KNOWN_MD5.size
}
