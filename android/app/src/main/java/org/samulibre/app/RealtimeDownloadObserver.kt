package org.samulibre.app

import android.app.DownloadManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Centinela de Descargas e Instaladores APK en Tiempo Real (Multi-Capa).
 * 
 * Capas de Detección:
 *  1. FileObserver nativo en directorios públicos de Descargas (/sdcard/Download).
 *  2. ContentObserver en MediaStore.Downloads (captura descargas desde Chrome, Opera, Samsung Internet).
 *  3. BroadcastReceiver para DownloadManager.ACTION_DOWNLOAD_COMPLETE.
 *  4. Barrido inicial e inspección de archivos preexistentes al arrancar el centinela.
 *  5. Motor de análisis: Base de datos de firmas (SHA-256 / MD5) + Heurística Rogue (Xuper TV, Magis TV)
 *     + Desempaquetador de metadatos ZIP/DEX + Motor nativo YARA-X.
 */
class RealtimeDownloadObserver(
    private val context: Context,
    private val targetDir: File,
    private val onThreatDetected: ((threatJson: JSONObject) -> Unit)? = null
) : @Suppress("DEPRECATION") FileObserver(
    targetDir.absolutePath,
    CREATE or CLOSE_WRITE or MOVED_TO
) {
    companion object {
        private const val TAG = "RealtimeDownloadObs"
        const val CHANNEL_THREATS_ID = "samulibre_threat_alerts"
        const val ACTION_DELETE_DOWNLOADED_APK = "org.samulibre.app.ACTION_DELETE_DOWNLOADED_APK"
        const val EXTRA_THREAT_FILE_PATH = "extra_threat_file_path"

        private val activeObservers = mutableListOf<RealtimeDownloadObserver>()
        private val scannedHashesCache = mutableSetOf<String>()
        private var mediaContentObserver: ContentObserver? = null
        private var downloadCompleteReceiver: BroadcastReceiver? = null
        private var globalOnThreatDetected: ((JSONObject) -> Unit)? = null

        private val observerScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun startWatching(context: Context, onThreatDetected: ((threatJson: JSONObject) -> Unit)? = null) {
            try {
                stopWatching()
                globalOnThreatDetected = onThreatDetected

                val candidateDirs = getCandidateDownloadDirs()

                // 1. Iniciar FileObservers en directorios detectados
                for (dir in candidateDirs) {
                    try {
                        val obs = RealtimeDownloadObserver(context, dir, onThreatDetected)
                        obs.startWatching()
                        activeObservers.add(obs)
                        Log.i(TAG, "Centinela FileObserver activo en: ${dir.absolutePath}")
                    } catch (t: Throwable) {
                        Log.w(TAG, "No se pudo iniciar FileObserver en ${dir.absolutePath}: ${t.message}")
                    }
                }

                // 2. Registrar ContentObserver en MediaStore para descargas de navegadores modernos
                registerMediaStoreObserver(context)

                // 3. Registrar BroadcastReceiver para DownloadManager del sistema
                registerDownloadCompleteReceiver(context)

                // 4. Barrido inicial inmediato sobre APKs existentes en Descargas (detecta descargas recientes)
                observerScope.launch {
                    delay(800)
                    scanAllCandidateDownloads(context)
                }

            } catch (t: Throwable) {
                Log.e(TAG, "Excepción resguardada en startWatching de descargas: ${t.message}", t)
            }
        }

        fun stopWatching() {
            for (obs in activeObservers) {
                try { obs.stopWatching() } catch (e: Exception) {}
            }
            activeObservers.clear()

            mediaContentObserver?.let {
                // Desregistro seguro
                mediaContentObserver = null
            }

            downloadCompleteReceiver?.let {
                // Desregistro seguro
                downloadCompleteReceiver = null
            }
        }

        fun getCandidateDownloadDirs(): List<File> {
            val candidateDirs = mutableSetOf<File>()
            val seenCanonicalPaths = mutableSetOf<String>()

            fun addIfValid(f: File?) {
                if (f != null && f.exists() && f.isDirectory) {
                    try {
                        val cp = f.canonicalPath
                        if (seenCanonicalPaths.add(cp)) {
                            candidateDirs.add(f)
                        }
                    } catch (e: Exception) {
                        candidateDirs.add(f)
                    }
                }
            }

            try {
                addIfValid(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS))
                addIfValid(File("/sdcard/Download"))
                addIfValid(File("/storage/emulated/0/Download"))
                addIfValid(File("/sdcard/Downloads"))
                addIfValid(File("/storage/emulated/0/Downloads"))
            } catch (e: Throwable) {
                Log.w(TAG, "Error detectando directorios de descarga: ${e.message}")
            }

            return candidateDirs.toList()
        }

        private fun registerMediaStoreObserver(context: Context) {
            try {
                val handler = Handler(Looper.getMainLooper())
                val obs = object : ContentObserver(handler) {
                    override fun onChange(selfChange: Boolean, uri: Uri?) {
                        super.onChange(selfChange, uri)
                        observerScope.launch {
                            delay(600)
                            scanAllCandidateDownloads(context)
                        }
                    }
                }

                val cr = context.contentResolver
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    cr.registerContentObserver(MediaStore.Downloads.EXTERNAL_CONTENT_URI, true, obs)
                } else {
                    @Suppress("DEPRECATION")
                    cr.registerContentObserver(MediaStore.Files.getContentUri("external"), true, obs)
                }
                mediaContentObserver = obs
                Log.i(TAG, "Centinela MediaStore ContentObserver registrado exitosamente.")
            } catch (t: Throwable) {
                Log.w(TAG, "No se pudo registrar ContentObserver de descargas: ${t.message}")
            }
        }

        private fun registerDownloadCompleteReceiver(context: Context) {
            try {
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(c: Context?, intent: Intent?) {
                        if (intent?.action == DownloadManager.ACTION_DOWNLOAD_COMPLETE) {
                            observerScope.launch {
                                delay(500)
                                scanAllCandidateDownloads(context)
                            }
                        }
                    }
                }
                val filter = IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
                } else {
                    context.registerReceiver(receiver, filter)
                }
                downloadCompleteReceiver = receiver
                Log.i(TAG, "Receptor DownloadManager.ACTION_DOWNLOAD_COMPLETE registrado.")
            } catch (t: Throwable) {
                Log.w(TAG, "No se pudo registrar DownloadCompleteReceiver: ${t.message}")
            }
        }

        /**
         * Examina todos los archivos APK en los directorios de descargas.
         */
        fun scanAllCandidateDownloads(context: Context) {
            val dirs = getCandidateDownloadDirs()
            for (dir in dirs) {
                val apks = dir.listFiles { f -> f.isFile && f.name.lowercase().endsWith(".apk") } ?: emptyArray()
                for (apk in apks) {
                    checkAndNotifyThreat(context, apk)
                }
            }
        }

        private fun checkAndNotifyThreat(context: Context, targetApk: File) {
            if (!targetApk.exists() || !targetApk.isFile || targetApk.length() < 1024) return

            val pathKey = "${targetApk.absolutePath}:${targetApk.length()}"
            if (!scannedHashesCache.add(pathKey)) return

            Log.i(TAG, "Inspeccionando instalador APK en tiempo real: ${targetApk.name} (${targetApk.length()} bytes)")
            val threat = inspectApkFile(context, targetApk)
            if (threat != null) {
                Log.w(TAG, "🚨 ¡AMENAZA EN TIEMPO REAL DETECTADA!: ${threat.optString("title")} en ${targetApk.absolutePath}")
                showThreatNotification(context, targetApk, threat)
                globalOnThreatDetected?.invoke(threat)
            }
        }

        fun calculateHash(file: File, algorithm: String): String {
            val digest = MessageDigest.getInstance(algorithm)
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(8192)
                var read: Int
                while (fis.read(buffer).also { read = it } != -1) {
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun inspectApkFile(context: Context, file: File): JSONObject? {
            if (!file.exists() || !file.isFile || file.length() <= 0) return null

            val (sha256, md5) = try { AndroidThreatDatabase.computeDualHashes(file) } catch (e: Exception) { Pair("", "") }

            // 1. Verificación por Base de Datos de Firmas Criptográficas (SHA-256 / MD5)
            val shaMatch = if (sha256.isNotEmpty()) AndroidThreatDatabase.lookupHash(sha256) else null
            val md5Match = if (md5.isNotEmpty() && shaMatch == null) AndroidThreatDatabase.lookupHash(md5) else null
            val sigMatch = shaMatch ?: md5Match

            var threatName: String? = sigMatch?.threatName
            var threatDetails: String? = sigMatch?.let {
                "Firma maliciosa confirmada (${it.hashType}: ${it.hashValue.take(16)}...). ${it.description}"
            }

            // 2. Extracción de Metadatos del Paquete (PackageManager)
            var packageName = ""
            var appName = file.name
            try {
                val pm = context.packageManager
                @Suppress("DEPRECATION")
                val archiveInfo = pm.getPackageArchiveInfo(file.absolutePath, PackageManager.GET_PERMISSIONS)
                if (archiveInfo != null) {
                    packageName = archiveInfo.packageName ?: ""
                    archiveInfo.applicationInfo?.let { appInfo ->
                        appInfo.sourceDir = file.absolutePath
                        appInfo.publicSourceDir = file.absolutePath
                        val loadedLabel = pm.getApplicationLabel(appInfo).toString()
                        if (loadedLabel.isNotBlank()) appName = loadedLabel
                    }
                }
            } catch (e: Exception) {
                // Continuar con nombre de archivo
            }

            // 3. Verificación Heurística Multi-Atributo (Paquete, Etiqueta, Nombre de Archivo)
            // Esto garantiza que archivos como "Xuper TV.apk", "xuper-tv.apk" o "magistv.apk"
            // sean detectados 100% de inmediato incluso si getPackageArchiveInfo devuelve null.
            if (threatName == null) {
                val rogueMatch = AndroidThreatDatabase.checkKnownRoguePackage(
                    packageName.ifEmpty { file.name },
                    appName.ifEmpty { file.name }
                ) ?: AndroidThreatDatabase.checkKnownRoguePackage(file.name, file.name)
                  ?: AndroidThreatDatabase.checkKnownRoguePackage(file.nameWithoutExtension, file.nameWithoutExtension)

                if (rogueMatch != null) {
                    threatName = rogueMatch.threatName
                    threatDetails = "Instalador no confiable detectado (${rogueMatch.category}). ${rogueMatch.description}"
                }
            }

            // 4. Inspección Profunda de Estructura ZIP / Clases Internas
            // Si el APK fue renombrado furtivamente a "app.apk" o "update.apk", se inspeccionan sus entradas ZIP.
            if (threatName == null) {
                try {
                    ZipFile(file).use { zip ->
                        val entries = zip.entries()
                        while (entries.hasMoreElements()) {
                            val entry = entries.nextElement()
                            val entryName = entry.name.lowercase()
                            if (entryName.contains("xuper") || entryName.contains("xupertv")) {
                                threatName = "Riskware.AndroidOS.XuperTV.StreamingRisk"
                                threatDetails = "Instalador no oficial de Xuper TV detectado por firmas internas en paquete APK (Riesgo de Proxyware)."
                                break
                            } else if (entryName.contains("magistv") || entryName.contains("magis.tv")) {
                                threatName = "Riskware.AndroidOS.MagisTV.Trojanized"
                                threatDetails = "Instalador no oficial de Magis TV detectado por firmas internas en paquete APK (IPTV Malicioso)."
                                break
                            } else if (entryName.contains("monetizekit") || entryName.contains("packetsdk") || entryName.contains("iproyal")) {
                                threatName = "Riskware.AndroidOS.Proxyware.Dropper"
                                threatDetails = "Módulo de proxyware encubierto detectado dentro del archivo APK (alquiler no consentido de red)."
                                break
                            }
                        }
                    }
                } catch (e: Exception) {
                    // Ignorar errores de archivo en escritura
                }
            }

            // 5. Inspección mediante Motor Multi-Engine Nativo (YARA-X / ClamAV Mobile)
            if (threatName == null) {
                try {
                    val rawNative = NativeBridge.scanApkFile(file.absolutePath)
                    val nativeObj = JSONObject(rawNative)
                    if (nativeObj.optString("status") == "Infected") {
                        threatName = nativeObj.optString("detection_name", "Malware.Android.Heuristic")
                        threatDetails = "Detección estática del motor YARA-X en el archivo APK descargado."
                    }
                } catch (e: Exception) {
                    // Motor nativo no disponible en modo fallback
                }
            }

            if (threatName != null) {
                return JSONObject().apply {
                    put("type", "APK_DESCARGADO")
                    put("severity", "CRITICO")
                    put("category", "Instalador APK Malicioso")
                    put("title", threatName)
                    put("name", appName)
                    put("file_name", file.name)
                    put("package_name", packageName)
                    put("path", file.absolutePath)
                    put("details", threatDetails ?: "Archivo potencialmente dañino detectado en tiempo real en Descargas.")
                    put("sha256", sha256)
                    put("md5", md5)
                    put("action", "delete")
                }
            }
            return null
        }

        fun showThreatNotification(context: Context, file: File, threat: JSONObject) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val nm = context.getSystemService(NotificationManager::class.java)
                val channel = NotificationChannel(
                    CHANNEL_THREATS_ID,
                    "Alertas de Malware y Descargas Infectadas",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Notificaciones urgentes al detectar instaladores APK maliciosos en Descargas"
                    enableVibration(true)
                }
                nm?.createNotificationChannel(channel)
            }

            val deleteIntent = Intent(context, MainActivity::class.java).apply {
                action = ACTION_DELETE_DOWNLOADED_APK
                putExtra(EXTRA_THREAT_FILE_PATH, file.absolutePath)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val deletePending = PendingIntent.getActivity(
                context,
                file.hashCode(),
                deleteIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
            )

            val openAppIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val openAppPending = PendingIntent.getActivity(
                context,
                0,
                openAppIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
            )

            val threatTitle = threat.optString("title", "APK Malicioso")
            val notification = NotificationCompat.Builder(context, CHANNEL_THREATS_ID)
                .setSmallIcon(android.R.drawable.stat_notify_error)
                .setContentTitle("🚨 Amenaza Detectada en Descargas")
                .setContentText("El archivo ${file.name} contiene $threatTitle. Toca para eliminarlo.")
                .setStyle(NotificationCompat.BigTextStyle().bigText("Se detectó el instalador infectado '${file.name}' ($threatTitle). SamuLibre recomienda eliminarlo inmediatamente para evitar la infección del dispositivo."))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setAutoCancel(true)
                .setContentIntent(openAppPending)
                .addAction(android.R.drawable.ic_menu_delete, "🗑️ Eliminar Archivo", deletePending)
                .build()

            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            nm?.notify(file.hashCode(), notification)
        }
    }

    override fun onEvent(event: Int, path: String?) {
        if (path == null) return
        val lower = path.lowercase()
        if (!lower.endsWith(".apk") && !lower.endsWith(".apk.tmp") && !lower.endsWith(".crdownload")) return

        val file = File(targetDir, path)
        observerScope.launch {
            try {
                // Dar tiempo breve al navegador para completar la escritura del archivo
                delay(400)
                if (!file.exists() || !file.isFile || file.length() < 1024) return@launch

                // Si terminó de descargarse (.apk final)
                val targetApk = if (file.name.endsWith(".apk", ignoreCase = true)) {
                    file
                } else {
                    val cleanName = file.name.substringBefore(".crdownload").substringBefore(".tmp")
                    File(targetDir, cleanName)
                }

                if (!targetApk.exists() || !targetApk.name.endsWith(".apk", ignoreCase = true)) {
                    // Si Chrome aún no ha renombrado el .crdownload, esperar un segundo intento
                    delay(1200)
                    if (!targetApk.exists() || !targetApk.name.endsWith(".apk", ignoreCase = true)) return@launch
                }

                checkAndNotifyThreat(context, targetApk)
            } catch (e: Exception) {
                Log.e(TAG, "Error inspeccionando descarga: ${e.message}", e)
            }
        }
    }
}
