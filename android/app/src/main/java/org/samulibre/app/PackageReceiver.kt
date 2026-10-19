package org.samulibre.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PackageReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action
        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            val packageName = intent.data?.schemeSpecificPart ?: return

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val pm = context.packageManager
                    val appInfo = pm.getApplicationInfo(packageName, 0)
                    val apkPath = appInfo.sourceDir

                    // Escanear APK con el motor nativo Multi-Engine (YARA-X + ClamAV Mobile)
                    val scanResultJson = NativeBridge.scanApkFile(apkPath)
                    System.out.println("SamuLibre Package Scan for $packageName: $scanResultJson")
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
    }
}
