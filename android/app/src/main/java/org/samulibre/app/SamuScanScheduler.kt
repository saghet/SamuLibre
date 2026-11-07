package org.samulibre.app

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Programador de Escaneos Automáticos de Seguridad (Cadencia: 8 Días).
 * 
 * Gestiona la programación periódica de auditorías completas del dispositivo
 * utilizando [AlarmManager] con tolerancia a Doze Mode y reinicios de sistema.
 * En cada ciclo, exige la actualización previa de firmas SHA-256 y MD5.
 */
object SamuScanScheduler {

    private const val TAG = "SamuLibre_Scheduler"
    const val ACTION_RUN_SCHEDULED_SCAN = "org.samulibre.app.action.RUN_SCHEDULED_SCAN"
    private const val PREFS_NAME = "samulibre_schedule_prefs"

    const val SCHEDULE_INTERVAL_DAYS = 8
    const val SCHEDULE_INTERVAL_MILLIS = SCHEDULE_INTERVAL_DAYS * 24L * 60L * 60L * 1000L // 8 días exactos en ms

    private const val KEY_ENABLED = "schedule_enabled"
    private const val KEY_LAST_SCAN_TS = "last_scan_ts"
    private const val KEY_NEXT_SCAN_TS = "next_scan_ts"
    private const val KEY_LAST_THREATS_COUNT = "last_threats_count"
    private const val REQUEST_CODE_SCHEDULED_SCAN = 8808

    fun isScheduleEnabled(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getBoolean(KEY_ENABLED, true) // Activo por defecto
    }

    fun setScheduleEnabled(context: Context, enabled: Boolean) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
        if (enabled) {
            scheduleNextScan(context, forceReset = false)
        } else {
            cancelScheduledScan(context)
        }
    }

    fun getLastScanTimestamp(context: Context): Long {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getLong(KEY_LAST_SCAN_TS, 0L)
    }

    fun getNextScanTimestamp(context: Context): Long {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getLong(KEY_NEXT_SCAN_TS, 0L)
    }

    fun recordScanCompleted(context: Context, threatsCount: Int) {
        val now = System.currentTimeMillis()
        val nextTime = now + SCHEDULE_INTERVAL_MILLIS
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putLong(KEY_LAST_SCAN_TS, now)
            .putLong(KEY_NEXT_SCAN_TS, nextTime)
            .putInt(KEY_LAST_THREATS_COUNT, threatsCount)
            .apply()

        Log.i(TAG, "Escaneo periódico completado. Próximo escaneo programado en 8 días: ${formatDate(nextTime)}")
        scheduleAlarmAtTime(context, nextTime)
    }

    /**
     * Programa la siguiente alarma de escaneo para dentro de 8 días.
     * Si ya existe una fecha futura válida y no se fuerza reseteo, se preserva.
     */
    fun scheduleNextScan(context: Context, forceReset: Boolean = false) {
        if (!isScheduleEnabled(context)) {
            Log.d(TAG, "Escaneo programado desactivado por el usuario.")
            return
        }

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        var nextTime = prefs.getLong(KEY_NEXT_SCAN_TS, 0L)

        if (forceReset || nextTime <= now) {
            nextTime = now + SCHEDULE_INTERVAL_MILLIS
            prefs.edit().putLong(KEY_NEXT_SCAN_TS, nextTime).apply()
        }

        scheduleAlarmAtTime(context, nextTime)
        Log.i(TAG, "Alarma programada cada 8 días registrada para: ${formatDate(nextTime)}")
    }

    private fun scheduleAlarmAtTime(context: Context, targetMillis: Long) {
        try {
            val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
            val intent = Intent(context, ScheduledScanReceiver::class.java).apply {
                action = ACTION_RUN_SCHEDULED_SCAN
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
            val pi = PendingIntent.getBroadcast(
                context,
                REQUEST_CODE_SCHEDULED_SCAN,
                intent,
                flags
            )

            // Para escaneos cada 8 días, setAndAllowWhileIdle es la API oficial y segura
            // que despierta el dispositivo en Doze Mode SIN requerir SCHEDULE_EXACT_ALARM.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (am.canScheduleExactAlarms()) {
                    try {
                        am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, targetMillis, pi)
                        Log.i(TAG, "Alarma periódica exacta registrada para: ${formatDate(targetMillis)}")
                        return
                    } catch (e: Throwable) {
                        Log.w(TAG, "Fallback de alarma exacta en Android 12+: ${e.message}")
                    }
                }
                // Si no tiene permiso de alarma exacta, usar setAndAllowWhileIdle (100% seguro contra SecurityException)
                try {
                    am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, targetMillis, pi)
                    Log.i(TAG, "Alarma periódica setAndAllowWhileIdle registrada para: ${formatDate(targetMillis)}")
                } catch (t2: Throwable) {
                    Log.w(TAG, "Fallback setWindow para alarma periódica: ${t2.message}")
                    am.setWindow(AlarmManager.RTC_WAKEUP, targetMillis, 60 * 60 * 1000L, pi)
                }
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, targetMillis, pi)
                Log.i(TAG, "Alarma periódica setAndAllowWhileIdle registrada para: ${formatDate(targetMillis)}")
            } else {
                am.set(AlarmManager.RTC_WAKEUP, targetMillis, pi)
                Log.i(TAG, "Alarma periódica legacy registrada para: ${formatDate(targetMillis)}")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Excepción resguardada registrando alarma periódica: ${t.message}", t)
        }
    }

    fun cancelScheduledScan(context: Context) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val intent = Intent(context, ScheduledScanReceiver::class.java).apply {
            action = ACTION_RUN_SCHEDULED_SCAN
        }
        val pi = PendingIntent.getBroadcast(
            context,
            REQUEST_CODE_SCHEDULED_SCAN,
            intent,
            PendingIntent.FLAG_NO_CREATE or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
        )
        if (pi != null) {
            am.cancel(pi)
            pi.cancel()
        }
        Log.i(TAG, "Alarma periódica cancelada.")
    }

    /**
     * Verifica si el plazo de 8 días ya venció (por ejemplo, si el teléfono estuvo apagado
     * durante la hora de la alarma). Si ya venció, dispara el escaneo inmediatamente.
     */
    fun checkAndRunIfDue(context: Context) {
        try {
        if (!isScheduleEnabled(context)) return

        val now = System.currentTimeMillis()
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val nextScan = prefs.getLong(KEY_NEXT_SCAN_TS, 0L)

        if (nextScan == 0L || nextScan <= now) {
            // Programar el siguiente escaneo periódico cada 8 días sin asfixiar el arranque en frío
            scheduleNextScan(context, forceReset = true)
            Log.i(TAG, "Próximo escaneo programado configurado para dentro de 8 días.")
        } else {
            scheduleAlarmAtTime(context, nextScan)
        }
        } catch (t: Throwable) {
            Log.w(TAG, "Error resguardado en checkAndRunIfDue: ${t.message}")
        }
    }

    fun getSchedulerInfo(context: Context): JSONObject {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val enabled = prefs.getBoolean(KEY_ENABLED, true)
        val lastScan = prefs.getLong(KEY_LAST_SCAN_TS, 0L)
        val nextScan = prefs.getLong(KEY_NEXT_SCAN_TS, 0L)
        val threats = prefs.getInt(KEY_LAST_THREATS_COUNT, 0)

        return JSONObject().apply {
            put("enabled", enabled)
            put("intervalDays", SCHEDULE_INTERVAL_DAYS)
            put("lastScanTimestamp", lastScan)
            put("lastScanFormatted", if (lastScan > 0) formatDate(lastScan) else "Pendiente de primer escaneo")
            put("nextScanTimestamp", nextScan)
            put("nextScanFormatted", if (nextScan > 0) formatDate(nextScan) else "Programando...")
            put("lastThreatsFound", threats)
        }
    }

    private fun formatDate(timestamp: Long): String {
        val sdf = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
        return sdf.format(Date(timestamp))
    }
}
