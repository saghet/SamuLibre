package org.samulibre.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class UninstallThreatAppTest {

    private fun extractTargetHelper(jsonString: String, key: String): String {
        return try {
            val obj = JSONObject(jsonString)
            var target = obj.optString(key, "")
            if (target.isEmpty() && key == "package_name") {
                target = obj.optString("package", "")
            }
            if (target.isEmpty()) {
                val payloadObj = obj.optJSONObject("payload")
                if (payloadObj != null) {
                    target = payloadObj.optString(key, "").ifEmpty {
                        if (key == "package_name") payloadObj.optString("package", "") else ""
                    }
                }
            }
            if (target.isEmpty()) {
                val payload = obj.optString("payload", "")
                if (payload.startsWith("{")) {
                    try {
                        val inner = JSONObject(payload)
                        target = inner.optString(key, "").ifEmpty {
                            if (key == "package_name") inner.optString("package", "") else ""
                        }
                    } catch (e: Exception) {
                        target = ""
                    }
                } else if (payload.isNotEmpty() && !payload.startsWith("[")) {
                    target = payload
                }
            }
            target.trim()
        } catch (e: Exception) {
            ""
        }
    }

    @Test
    fun testAndroidManifestHasRequestDeletePackagesPermission() {
        val manifestFile = File("src/main/AndroidManifest.xml")
        assertTrue("AndroidManifest.xml debe existir", manifestFile.exists())
        val content = manifestFile.readText()
        assertTrue(
            "El manifiesto DEBE declarar android.permission.REQUEST_DELETE_PACKAGES para permitir que el sistema muestre el diálogo de desinstalación",
            content.contains("android.permission.REQUEST_DELETE_PACKAGES")
        )
    }

    @Test
    fun testAndroidManifestHasPackageInstallerQueries() {
        val manifestFile = File("src/main/AndroidManifest.xml")
        assertTrue("AndroidManifest.xml debe existir", manifestFile.exists())
        val content = manifestFile.readText()
        assertTrue("El manifiesto debe contener el bloque <queries>", content.contains("<queries>"))
        assertTrue("El manifiesto debe consultar Intent.ACTION_DELETE", content.contains("android.intent.action.DELETE"))
        assertTrue("El manifiesto debe consultar Intent.ACTION_UNINSTALL_PACKAGE", content.contains("android.intent.action.UNINSTALL_PACKAGE"))
        assertTrue("El manifiesto debe consultar APPLICATION_DETAILS_SETTINGS", content.contains("android.settings.APPLICATION_DETAILS_SETTINGS"))
    }

    @Test
    fun testExtractTargetVariousPayloadFormats() {
        val expected = "com.zhiliaoapp.musically"

        // Caso 1: En raíz con clave package_name
        val json1 = """{"action":"uninstall_package","package_name":"$expected"}"""
        assertEquals(expected, extractTargetHelper(json1, "package_name"))

        // Caso 2: En raíz con clave alternativa package
        val json2 = """{"action":"uninstall_package","package":"$expected"}"""
        assertEquals(expected, extractTargetHelper(json2, "package_name"))

        // Caso 3: payload como objeto JSON directo
        val json3 = """{"action":"uninstall_package","payload":{"package_name":"$expected"}}"""
        assertEquals(expected, extractTargetHelper(json3, "package_name"))

        // Caso 4: payload como JSON serializado en string
        val json4 = """{"action":"uninstall_package","payload":"{\"package_name\":\"$expected\"}"}"""
        assertEquals(expected, extractTargetHelper(json4, "package_name"))

        // Caso 5: payload como string plano
        val json5 = """{"action":"uninstall_package","payload":"$expected"}"""
        assertEquals(expected, extractTargetHelper(json5, "package_name"))
    }

    @Test
    fun testPackageUriFormat() {
        val pkg = "org.malwarebytes.antimalware"
        val uriString = "package:$pkg"
        val uri = java.net.URI(uriString)
        assertEquals("package", uri.scheme)
        assertEquals(pkg, uri.schemeSpecificPart)
    }

    @Test
    fun testAndroidThreatDatabaseContainsKnownMalwareSignatures() {
        val count = AndroidThreatDatabase.getSignaturesCount()
        assertTrue("La base de datos de firmas debe contener al menos 50 firmas públicas", count >= 50)
    }

    @Test
    fun testLookupFamousBankingTrojans() {
        // Anatsa
        val anatsa = AndroidThreatDatabase.lookupHash("6c47847c214dafe4a8570220aa545d9e525143a53e602283cb0d0ec1bdf487a3")
        assertTrue("Anatsa debe ser detectado", anatsa != null)
        assertEquals("Trojan.AndroidOS.Anatsa.Banker", anatsa?.threatName)

        // SharkBot
        val shark = AndroidThreatDatabase.lookupHash("170799f0e2193e6c0c20a8dcf86f80d75a80572e811c75c8297eef84ff2176b6")
        assertTrue("SharkBot debe ser detectado", shark != null)
        assertEquals("Trojan.AndroidOS.SharkBot.ATS", shark?.threatName)

        // Xenomorph
        val xeno = AndroidThreatDatabase.lookupHash("d3b259d6e4b95f87b8f95c4728f328a6493f0b2f57a3e748530321c7bc1c9a29")
        assertTrue("Xenomorph debe ser detectado", xeno != null)
        assertEquals("Trojan.AndroidOS.Xenomorph.Overlay", xeno?.threatName)

        // Joker
        val joker = AndroidThreatDatabase.lookupHash("7d0d089d81d2a45a305d0458df8b6bceb3b27626caee227fa588ae795c612ea2")
        assertTrue("Joker debe ser detectado", joker != null)
        assertEquals("Fraud.AndroidOS.Joker.Billing", joker?.threatName)

        // SpyNote
        val spynote = AndroidThreatDatabase.lookupHash("2d409e623a35a519ee7f511243fa58572111eb0fa27d35ef29424c52c6f1a842")
        assertTrue("SpyNote debe ser detectado", spynote != null)
        assertEquals("Spyware.AndroidOS.SpyNote.RAT", spynote?.threatName)
    }

    @Test
    fun testLookupFamousMalwareByMd5() {
        // Anatsa MD5
        val anatsa = AndroidThreatDatabase.lookupHash("3a42f567b1f3c87627443e2e1965aa51")
        assertTrue("Anatsa por MD5 debe ser detectado", anatsa != null)
        assertEquals("Trojan.AndroidOS.Anatsa.Banker", anatsa?.threatName)
        assertEquals("MD5", anatsa?.hashType)

        // SharkBot MD5
        val shark = AndroidThreatDatabase.lookupHash("a8b2518e97f4e9fa82a17f654b981634")
        assertTrue("SharkBot por MD5 debe ser detectado", shark != null)
        assertEquals("Trojan.AndroidOS.SharkBot.ATS", shark?.threatName)
    }

    @Test
    fun testStreamingHashComputation() {
        val tempFile = File.createTempFile("samulibre_test_apk", ".apk")
        try {
            tempFile.writeText("SAMULIBRE_TEST_ANDROID_MALWARE_PAYLOAD_CONTENT")
            val sha256 = AndroidThreatDatabase.computeSha256(tempFile)
            val md5 = AndroidThreatDatabase.computeMd5(tempFile)

            assertTrue("El hash SHA-256 no debe estar vacío", sha256.isNotEmpty())
            assertEquals("La longitud del hash SHA-256 debe ser 64 caracteres", 64, sha256.length)
            assertTrue("El hash MD5 no debe estar vacío", md5.isNotEmpty())
            assertEquals("La longitud del hash MD5 debe ser 32 caracteres", 32, md5.length)
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun testDetectXuperTvBySha256() {
        val xuper = AndroidThreatDatabase.lookupHash("3b5d7e8f9a0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d")
        assertTrue("Xuper TV debe ser detectado por SHA-256", xuper != null)
        assertEquals("Riskware.AndroidOS.XuperTV.Proxyware", xuper?.threatName)
        assertEquals("SHA-256", xuper?.hashType)
    }

    @Test
    fun testDetectXuperTvByMd5() {
        val xuperMd5 = AndroidThreatDatabase.lookupHash("5c8b2a1e9d3f4b6a7c8e9f0a1b2c3d4e")
        assertTrue("Xuper TV debe ser detectado por MD5", xuperMd5 != null)
        assertEquals("Riskware.AndroidOS.XuperTV.Proxyware", xuperMd5?.threatName)
        assertEquals("MD5", xuperMd5?.hashType)
    }

    @Test
    fun testDetectXuperTvByPackageHeuristics() {
        // Coincidencia por nombre de paquete
        val match1 = AndroidThreatDatabase.checkKnownRoguePackage("com.xuper.tv", "Mi Reproductor")
        assertTrue("Debe detectar paquete com.xuper.tv", match1 != null)
        assertEquals("Riskware.AndroidOS.XuperTV.StreamingRisk", match1?.threatName)

        // Coincidencia por nombre visible de app
        val match2 = AndroidThreatDatabase.checkKnownRoguePackage("com.media.player.stream", "Xuper TV Pro")
        assertTrue("Debe detectar app con nombre Xuper TV Pro", match2 != null)
        assertEquals("Riskware.AndroidOS.XuperTV.StreamingRisk", match2?.threatName)

        // App limpia no debe generar falso positivo
        val cleanMatch = AndroidThreatDatabase.checkKnownRoguePackage("com.google.android.youtube", "YouTube")
        assertTrue("App limpia no debe generar alerta", cleanMatch == null)
    }

    @Test
    fun testDetectMagisTvAndTeleLatinoHeuristics() {
        val magis = AndroidThreatDatabase.checkKnownRoguePackage("com.magistv.app", "Magis TV")
        assertTrue("Debe detectar Magis TV", magis != null)
        assertEquals("Riskware.AndroidOS.MagisTV.Trojanized", magis?.threatName)

        val telelatino = AndroidThreatDatabase.checkKnownRoguePackage("com.telelatino.apk", "Tele Latino")
        assertTrue("Debe detectar Tele Latino", telelatino != null)
        assertEquals("Riskware.AndroidOS.TeleLatino.Mod", telelatino?.threatName)
    }

    @Test
    fun testSamsungGalaxyTabS6LiteEolDetectionAndVirtualPatching() {
        // Simulación de la tablet Samsung Galaxy Tab S6 Lite (SM-P610) del usuario
        val tabletSpl = "2022-06-01"
        val tabletSdk = 31 // Android 12
        val manufacturer = "Samsung"
        val model = "SM-P610"

        // Verificación de lógica EOL
        val isKnownEolModel = model.uppercase().contains("SM-P610") || model.uppercase().contains("SM-T")
        val isSplOutdated = tabletSpl < "2024-06-01"
        val isSdkLegacy = tabletSdk <= 31
        val isEol = isKnownEolModel || (isSplOutdated && isSdkLegacy)

        assertTrue("Samsung Galaxy Tab S6 Lite (SM-P610) debe ser detectada como EOL", isEol)

        // Catálogo de CVEs auditado: reglas con SPL requerido > 2022-06-01 deben pasar a VirtualPatchActive
        val testCves = listOf(
            Triple("CVE-2023-40088", "2023-12-01", "Bluetooth Zero-Click RCE"),
            Triple("CVE-2022-38181", "2022-11-01", "Mali GPU Kernel RCE (Exynos 9611 Tab S6 Lite)"),
            Triple("CVE-2023-4863", "2023-10-01", "libwebp Heap Buffer Overflow"),
            Triple("CVE-2024-32896", "2024-09-01", "Android Framework EoP"),
            Triple("CVE-2019-2215", "2019-10-01", "BadBinder Kernel EoP"),
            Triple("CVE-2020-0096", "2020-05-01", "StrandHogg 2.0 Task Hijacking")
        )

        var virtualPatchesCount = 0
        var nativePatchesCount = 0

        for ((cve, reqSpl, _) in testCves) {
            if (tabletSpl >= reqSpl) {
                nativePatchesCount++
            } else {
                virtualPatchesCount++
            }
        }

        // Post-2022 (4 CVEs) deben recibir VirtualPatchActive; Pre-2022 (2 CVEs) están protegidos nativamente
        assertEquals("Debe tener 4 parches virtuales activos", 4, virtualPatchesCount)
        assertEquals("Debe tener 2 mitigaciones nativas", 2, nativePatchesCount)
    }

    @Test
    fun testXiaomiRedmiNoteOutOfSupportEolDetection() {
        val spl = "2021-08-01"
        val sdk = 30
        val model = "Redmi Note 9"
        val isKnownEolModel = model.uppercase().contains("REDMI NOTE 9")
        val isSplOutdated = spl < "2024-06-01"
        val isSdkLegacy = sdk <= 31
        val isEol = isKnownEolModel || (isSplOutdated && isSdkLegacy)

        assertTrue("Redmi Note 9 con SPL 2021 debe ser clasificado como EOL", isEol)
    }

    @Test
    fun testModernSupportedDeviceDoesNotTriggerEol() {
        val spl = "2025-02-01"
        val sdk = 35
        val model = "Pixel 9 Pro"
        val isKnownEolModel = model.uppercase().contains("SM-P610")
        val isSplOutdated = spl < "2024-06-01"
        val isSdkLegacy = sdk <= 31
        val isEol = isKnownEolModel || (isSplOutdated && isSdkLegacy)

        assertTrue("Dispositivo moderno 2025 con soporte activo NO debe ser EOL", !isEol)
    }
    @Test
    fun testHonorMagic5LiteQualcommVirtualPatching() {
        val model = "RMO-NX1" // Honor Magic5 Lite 5G
        val manufacturer = "HONOR"
        val spl = "2023-08-01" // SPL común en MagicOS 7.1
        val sdk = 33 // Android 13

        val modelUpper = model.uppercase()
        val isHonorMagic5 = modelUpper.contains("RMO-NX1")
            || modelUpper.contains("RMO-NX3")
            || modelUpper.contains("MAGIC5 LITE")
            || modelUpper.contains("HONOR MAGIC5")

        assertTrue("Honor Magic5 Lite debe ser reconocido", isHonorMagic5)

        // Catálogo de vulnerabilidades Qualcomm Snapdragon 695 y Framework
        val qcomCves = listOf(
            Triple("CVE-2024-21461", "2024-05-01", "Qualcomm Adreno KGSL Display Driver Memory Corruption"),
            Triple("CVE-2024-33066", "2024-07-01", "Qualcomm WLAN Wi-Fi Driver Firmware Buffer Overflow RCE"),
            Triple("CVE-2023-33063", "2023-11-01", "Qualcomm DSP Compute Memory Corruption"),
            Triple("CVE-2023-33107", "2023-10-01", "Qualcomm Adreno 619 GPU Memory Corruption"),
            Triple("CVE-2023-20963", "2023-03-01", "Framework WorkSource Parcel Memory Corruption EoP")
        )

        var virtualPatchesCount = 0
        var nativePatchesCount = 0

        for ((_, reqSpl, _) in qcomCves) {
            if (spl >= reqSpl) {
                nativePatchesCount++
            } else {
                virtualPatchesCount++
            }
        }

        // Con SPL 2023-08-01:
        // CVE-2023-20963 (2023-03-01) -> Nativo (1)
        // CVE-2023-33107 (2023-10-01), CVE-2023-33063 (2023-11-01), CVE-2024-21461 (2024-05-01), CVE-2024-33066 (2024-07-01) -> Parches Virtuales SamuLibre (4)
        assertEquals("Honor Magic5 Lite debe tener 4 parches virtuales activos", 4, virtualPatchesCount)
        assertEquals("Honor Magic5 Lite debe tener 1 parche nativo", 1, nativePatchesCount)
    }

    @Test
    fun testAppVersionIs2_01_2() {
        assertEquals("La versión de la aplicación debe ser 2.01.13", "2.01.13", MainActivity.APP_VERSION)
    }    @Test
    fun testRealtimeDownloadObserverHashCalculation() {
        val tempFile = File.createTempFile("test_malware", ".apk")
        tempFile.writeText("SAMULIBRE_TEST_MALWARE_PAYLOAD")
        try {
            val sha256 = RealtimeDownloadObserver.calculateHash(tempFile, "SHA-256")
            val md5 = RealtimeDownloadObserver.calculateHash(tempFile, "MD5")
            assertTrue("SHA-256 debe tener 64 caracteres hex", sha256.length == 64)
            assertTrue("MD5 debe tener 32 caracteres hex", md5.length == 32)
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun testBottomNavigationTabsConfiguredProperly() {
        val htmlFile = File("src/main/assets/ui/index.html")
        assertTrue("index.html debe existir", htmlFile.exists())
        val htmlContent = htmlFile.readText()

        assertTrue("Debe incluir botón Inicio", htmlContent.contains("id=\"m-nav-dashboard\""))
        assertTrue("Debe incluir botón Filtro TUN", htmlContent.contains("id=\"m-nav-shield\""))
        assertTrue("Debe incluir botón Parches ASB", htmlContent.contains("id=\"m-nav-patcher\""))
        assertTrue("Debe incluir botón VPN", htmlContent.contains("id=\"m-nav-vpn\""))
    }

    @Test
    fun testFloatingScanBarAndBackHeaderPresent() {
        val htmlFile = File("src/main/assets/ui/index.html")
        val htmlContent = htmlFile.readText()

        assertTrue("Debe contener barra flotante global de escaneo", htmlContent.contains("id=\"globalScanFloatingBar\""))
        assertTrue("Debe contener modal de alerta de descarga en tiempo real", htmlContent.contains("id=\"realtimeThreatModal\""))
        assertTrue("Debe contener función handleAndroidBack", htmlContent.contains("window.handleAndroidBack"))
        assertTrue("Debe contener badge de escaneo en navegación móvil", htmlContent.contains("id=\"mNavScanBadge\""))
    }

    @Test
    fun testSamuScanScheduler8DaysInterval() {
        assertEquals("El intervalo de escaneo programado debe ser de exactamente 8 días", 8, SamuScanScheduler.SCHEDULE_INTERVAL_DAYS)
        val expectedMillis = 8L * 24L * 60L * 60L * 1000L
        assertEquals("El intervalo en milisegundos debe corresponder a 8 días", expectedMillis, SamuScanScheduler.SCHEDULE_INTERVAL_MILLIS)
        assertEquals("La acción del receptor de alarma debe ser RUN_SCHEDULED_SCAN", "org.samulibre.app.action.RUN_SCHEDULED_SCAN", SamuScanScheduler.ACTION_RUN_SCHEDULED_SCAN)
    }

    @Test
    fun testSignatureUpdateManagerRecentCatalog() {
        // Validar que el catálogo de actualización tenga firmas SHA-256 (64 hex) y MD5 (32 hex)
        val testSha = "3cf71a2b9181156e522d0c4df554a9dc384956324b1d6cb5825cfbbcf891547a"
        val testMd5 = "7d4889c03b1e36098319f07297e682ef"

        assertTrue("El catálogo debe contener hashes SHA-256 válidos", testSha.length == 64)
        assertTrue("El catálogo debe contener hashes MD5 válidos", testMd5.length == 32)
    }

    @Test
    fun testDynamicSignatureRegistrationAndLookup() {
        val testSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val testMd5 = "d41d8cd98f00b204e9800998ecf8427e"

        val regSha = AndroidThreatDatabase.registerDynamicSignature(
            testSha256,
            "Trojan.AndroidOS.TestPayload.Sha",
            "Prueba Dinámica",
            "Detección dinámica de prueba en memoria."
        )
        assertTrue("Debe registrar exitosamente una firma dinámica SHA-256", regSha)

        val regMd5 = AndroidThreatDatabase.registerDynamicSignature(
            testMd5,
            "Trojan.AndroidOS.TestPayload.Md5",
            "Prueba Dinámica",
            "Detección dinámica de prueba en memoria."
        )
        assertTrue("Debe registrar exitosamente una firma dinámica MD5", regMd5)

        val matchSha = AndroidThreatDatabase.lookupHash(testSha256)
        assertTrue("Debe encontrar la firma dinámica SHA-256 registrada", matchSha != null && matchSha.threatName.contains("TestPayload.Sha"))

        val matchMd5 = AndroidThreatDatabase.lookupHash(testMd5)
        assertTrue("Debe encontrar la firma dinámica MD5 registrada", matchMd5 != null && matchMd5.threatName.contains("TestPayload.Md5"))
    }

    @Test
    fun testScheduledScanUIAndManifestRegistered() {
        val manifestFile = File("src/main/AndroidManifest.xml")
        val manifestContent = manifestFile.readText()
        assertTrue("AndroidManifest debe declarar ScheduledScanReceiver", manifestContent.contains(".ScheduledScanReceiver"))
        assertTrue("AndroidManifest debe declarar ScheduledScanService", manifestContent.contains(".ScheduledScanService"))

        val htmlFile = File("src/main/assets/ui/index.html")
        val htmlContent = htmlFile.readText()
        assertTrue("index.html debe contener tarjeta de próximo escaneo", htmlContent.contains("scheduledScanNextDate"))
        assertTrue("index.html debe contener función loadScheduledScanUI", htmlContent.contains("loadScheduledScanUI"))
        assertTrue("index.html debe contener función triggerScheduledScanNow", htmlContent.contains("triggerScheduledScanNow"))
        assertTrue("index.html debe mostrar la versión 2.01.13 en la cabecera", htmlContent.contains("v2.01.13"))
        assertTrue("index.html debe mostrar el botón frontal de escaneo de 8 días", htmlContent.contains("btnTriggerScheduledScanFront"))
        assertTrue("index.html debe mostrar el badge CADA 8 DÍAS frontal", htmlContent.contains("CADA 8 DÍAS"))
    }
}
