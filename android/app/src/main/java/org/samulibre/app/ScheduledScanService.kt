package org.samulibre.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File

/**
 * Servicio en primer plano para la ejecución desatendida del Escaneo Automático Periódico (Cada 8 Días).
 * 
 * Flujo obligatorio:
 * 1. Fase 1: Actualiza la base de firmas criptográficas SHA-256 y MD5 contra el catálogo de amenazas.
 * 2. Fase 2: Ejecuta el análisis profundo de todas las aplicaciones instaladas y archivos APK descargados.
 * 3. Fase 3: Emite alertas inmediatas si se descubren amenazas y reprograma el escaneo para 8 días después.
 */
class ScheduledScanService : Service() {

    companion object {
        private const val TAG = "SamuLibre_ScanService"
        private const val NOTIFICATION_ID = 9001
        private const val CHANNEL_ID = "samulibre_scheduled_scans"
        private const val ACTION_START_SCHEDULED_SCAN = "org.samulibre.app.action.START_SCHEDULED_SCAN"

        fun startScan(context: Context) {
            val intent = Intent(context, ScheduledScanService::class.java).apply {
                action = ACTION_START_SCHEDULED_SCAN
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            val initialNotif = buildNotification(
                "Iniciando escaneo programado cada 8 días...",
                "Fase 1/2: Actualizando base de firmas SHA-256 y MD5..."
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                } else {
                    0
                }
                if (fgsType != 0) {
                    try {
                        startForeground(NOTIFICATION_ID, initialNotif, fgsType)
                    } catch (t: Throwable) {
                        Log.w(TAG, "Fallback startForeground 2-param: ${t.message}")
                        startForeground(NOTIFICATION_ID, initialNotif)
                    }
                } else {
                    startForeground(NOTIFICATION_ID, initialNotif)
                }
            } else {
                startForeground(NOTIFICATION_ID, initialNotif)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "No se pudo vincular notificación ForegroundService: ${t.message}")
        }

        serviceScope.launch {
            try {
                executeScanPipeline()
            } catch (t: Throwable) {
                Log.e(TAG, "Error en ejecución de escaneo programado: ${t.message}", t)
            } finally {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                    } else {
                        @Suppress("DEPRECATION")
                        stopForeground(true)
                    }
                } catch (t: Throwable) {}
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    private suspend fun executeScanPipeline() {
        Log.i(TAG, "=== INICIO DE PIPELINE DE ESCANEO PROGRAMADO (CADA 8 DÍAS) ===")

        // -------------------------------------------------------------
        // FASE 1: ACTUALIZACIÓN OBLIGATORIA PREVIA DE FIRMAS SHA256/MD5
        // -------------------------------------------------------------
        updateNotification(
            "Actualizando Firmas de Amenazas",
            "Fase 1/2: Descargando y verificando firmas SHA-256 y MD5..."
        )

        val updateReport = SignatureUpdateManager.updateSignatures(this)
        Log.i(TAG, "Fase 1 completada: ${updateReport.message} (Total: ${updateReport.totalSignatures})")

        // -------------------------------------------------------------
        // FASE 2: ESCANEO DE APLICACIONES INSTALADAS Y APKS DESCARGADOS
        // -------------------------------------------------------------
        updateNotification(
            "Escaneo Automático de Seguridad",
            "Fase 2/2: Analizando apps y APKs con ${updateReport.totalSignatures} firmas activas..."
        )

        val threatsFound = mutableListOf<String>()

        // 2.1 Escaneo de aplicaciones instaladas
        val pm = packageManager
        val installedPackages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }

        for (pkg in installedPackages) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            val isUserApp = !isSystem || isUpdatedSystem

            if (isUserApp) {
                kotlinx.coroutines.yield()
                kotlinx.coroutines.delay(10)
                val appName = pm.getApplicationLabel(appInfo).toString()
                val apkPath = appInfo.sourceDir
                if (!apkPath.isNullOrEmpty()) {
                    val apkFile = File(apkPath)
                    val threatMatch = AndroidThreatDatabase.checkFileThreat(apkFile)
                    if (threatMatch != null) {
                        threatsFound.add("${threatMatch.threatName} en app: $appName (${pkg.packageName})")
                    } else {
                        val rogueMatch = AndroidThreatDatabase.checkKnownRoguePackage(pkg.packageName, appName)
                        if (rogueMatch != null) {
                            threatsFound.add("${rogueMatch.threatName} en app: $appName (${pkg.packageName})")
                        }
                    }
                }
            }
        }

        // 2.2 Escaneo de APKs descargados en /sdcard/Download
        val downloadDirs = listOfNotNull(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            File("/sdcard/Download"),
            File("/storage/emulated/0/Download")
        ).distinctBy { it.absolutePath }

        for (dir in downloadDirs) {
            if (dir.exists() && dir.isDirectory) {
                val apks = dir.listFiles { f -> f.isFile && f.name.lowercase().endsWith(".apk") } ?: emptyArray()
                for (apk in apks) {
                    kotlinx.coroutines.yield()
                    kotlinx.coroutines.delay(10)
                    val threatMatch = AndroidThreatDatabase.checkFileThreat(apk)
                    if (threatMatch != null) {
                        threatsFound.add("${threatMatch.threatName} en archivo APK: ${apk.name}")
                    } else {
                        val rogueMatch = AndroidThreatDatabase.checkKnownRoguePackage(apk.name, apk.name)
                        if (rogueMatch != null) {
                            threatsFound.add("${rogueMatch.threatName} en archivo APK: ${apk.name}")
                        }
                    }
                }
            }
        }

        Log.i(TAG, "Fase 2 completada. Amenazas encontradas: ${threatsFound.size}")

        // -------------------------------------------------------------
        // FASE 3: REPORTE, ALERTA Y REPROGRAMACIÓN
        // -------------------------------------------------------------
        SamuScanScheduler.recordScanCompleted(this, threatsFound.size)

        if (threatsFound.isNotEmpty()) {
            notifyThreatsAlert(threatsFound)
        } else {
            notifyScanClean(updateReport.totalSignatures)
        }
        
        Log.i(TAG, "=== FIN DE PIPELINE DE ESCANEO PROGRAMADO (REPROGRAMADO PARA 8 DÍAS) ===")
    }

    private fun notifyThreatsAlert(threats: List<String>) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pi = PendingIntent.getActivity(
            this,
            9002,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
        )

        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_samulibre_shield)
            .setContentTitle("⚠️ Amenazas encontradas en escaneo periódico")
            .setContentText("Se detectaron ${threats.size} amenazas críticas. Toca para desinstalarlas.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "El escaneo automático de 8 días ha detectado:\n" + threats.take(4).joinToString("\n• ", "• ") +
                if (threats.size > 4) "\n...y ${threats.size - 4} más." else ""
            ))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()

        nm.notify(9003, notif)
    }

    private fun notifyScanClean(totalSignatures: Int) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_samulibre_shield)
            .setContentTitle("✅ Escaneo periódico de 8 días completado")
            .setContentText("Dispositivo 100% limpio y protegido con $totalSignatures firmas.")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()

        nm.notify(9004, notif)
    }

    private fun updateNotification(title: String, message: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm?.notify(NOTIFICATION_ID, buildNotification(title, message))
    }

    private fun buildNotification(title: String, message: String) =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_samulibre_shield)
            .setContentTitle(title)
            .setContentText(message)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SamuLibre Escaneos Automáticos Periódicos",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Notificaciones del ciclo periódico de auditoría cada 8 días y actualización de firmas"
            }
            nm?.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}
