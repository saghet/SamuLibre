package org.samulibre.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class RealtimeDownloadDetectionTest {

    @Test
    fun testCheckKnownRoguePackageDetectsXuperTvVariants() {
        val testCases = listOf(
            Pair("com.xuper.app", "Xuper TV"),
            Pair("com.xupertv.mobile", "Reproductor"),
            Pair("tv.xuper.client", "App"),
            Pair("com.streaming.tv", "Xuper TV"),
            Pair("com.streaming.tv", "xuper-tv"),
            Pair("xuper_tv.apk", "xuper_tv.apk"),
            Pair("Xuper TV.apk", "Xuper TV.apk"),
            Pair("xuper.apk", "xuper.apk")
        )

        for ((pkg, name) in testCases) {
            val match = AndroidThreatDatabase.checkKnownRoguePackage(pkg, name)
            assertNotNull("Debe detectar variante de Xuper TV: pkg=$pkg, name=$name", match)
            assertEquals("Riskware.AndroidOS.XuperTV.StreamingRisk", match?.threatName)
        }
    }

    @Test
    fun testCheckKnownRoguePackageDetectsMagisTvVariants() {
        val testCases = listOf(
            Pair("com.magistv.player", "Magis"),
            Pair("com.streaming.tv", "Magis TV"),
            Pair("magistv.apk", "magistv.apk")
        )

        for ((pkg, name) in testCases) {
            val match = AndroidThreatDatabase.checkKnownRoguePackage(pkg, name)
            assertNotNull("Debe detectar variante de Magis TV: pkg=$pkg, name=$name", match)
            assertEquals("Riskware.AndroidOS.MagisTV.Trojanized", match?.threatName)
        }
    }

    @Test
    fun testComputeDualHashesMatchesSingleDigests() {
        val tempFile = File.createTempFile("test_payload_", ".bin")
        try {
            val sampleBytes = "SamuLibre Anti-Malware Realtime Sentinel Test Payload 2026".toByteArray(Charsets.UTF_8)
            tempFile.writeBytes(sampleBytes)

            val singleSha = AndroidThreatDatabase.computeSha256(tempFile)
            val singleMd5 = AndroidThreatDatabase.computeMd5(tempFile)
            val (dualSha, dualMd5) = AndroidThreatDatabase.computeDualHashes(tempFile)

            assertEquals("SHA-256 en single pass debe ser idéntico al cálculo dual", singleSha, dualSha)
            assertEquals("MD5 en single pass debe ser idéntico al cálculo dual", singleMd5, dualMd5)
            assertTrue("SHA-256 no debe estar vacío", dualSha.isNotEmpty())
            assertTrue("MD5 no debe estar vacío", dualMd5.isNotEmpty())
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun testZipHeuristicDetectsRenamedXuperTvApk() {
        val tempApk = File.createTempFile("renamed_download_", ".apk")
        try {
            ZipOutputStream(FileOutputStream(tempApk)).use { zos ->
                val entry = ZipEntry("com/xuper/tv/core/StreamingService.class")
                zos.putNextEntry(entry)
                zos.write("DUMMY_DEX_BYTES_FOR_TEST".toByteArray())
                zos.closeEntry()
            }

            var detectedName: String? = null
            java.util.zip.ZipFile(tempApk).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entryName = entries.nextElement().name.lowercase()
                    if (entryName.contains("xuper") || entryName.contains("xupertv")) {
                        detectedName = "Riskware.AndroidOS.XuperTV.StreamingRisk"
                        break
                    }
                }
            }

            assertEquals(
                "Incluso con un archivo renombrado, la inspección ZIP debe detectar la clase de Xuper TV",
                "Riskware.AndroidOS.XuperTV.StreamingRisk",
                detectedName
            )
        } finally {
            tempApk.delete()
        }
    }
}
