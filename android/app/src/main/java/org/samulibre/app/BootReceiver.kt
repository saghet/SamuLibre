package org.samulibre.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Receptor de eventos de arranque y actualización de SamuLibre (v2.00.4).
 * Asegura que el icono en la barra de estado y la tarjeta de acceso rápido a la VPN
 * se reanuden inmediatamente tras reiniciar el dispositivo o actualizar el paquete APK.
 */
class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "SamuLibre_BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED || action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            Log.i(TAG, "Evento de sistema recibido ($action): activando Cyber-Shield permanente")
            try {
                val serviceIntent = Intent(context, SamuVpnService::class.java).apply {
                    this.action = SamuVpnService.ACTION_START_SHIELD
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "No se pudo iniciar SamuVpnService tras arranque: ${t.message}")
            }
        }
    }
}
