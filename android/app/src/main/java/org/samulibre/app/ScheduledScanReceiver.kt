package org.samulibre.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Receptor de Alarma para el Escaneo Automático Periódico (Cada 8 Días).
 * Inicia el Foreground Service [ScheduledScanService] para asegurar la ejecución
 * continua y desatendida del análisis de seguridad y actualización de firmas.
 */
class ScheduledScanReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SamuLibre_ScanReceiver"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == SamuScanScheduler.ACTION_RUN_SCHEDULED_SCAN) {
            Log.i(TAG, "Alarma periódica de 8 días recibida. Iniciando ScheduledScanService...")
            try {
                ScheduledScanService.startScan(context)
            } catch (t: Throwable) {
                Log.e(TAG, "Fallo al iniciar ScheduledScanService desde receiver: ${t.message}", t)
            }
        }
    }
}
