package org.samulibre.app

object NativeBridge {
    init {
        try {
            System.loadLibrary("samulibre_android")
        } catch (e: UnsatisfiedLinkError) {
            System.err.println("Native library samulibre_android could not be loaded: ${e.message}")
        }
    }

    external fun initCore(appDataDir: String): Boolean
    external fun dispatchIpc(actionJson: String): String
    external fun processTunPacket(packet: ByteArray): String
    external fun scanApkFile(apkPath: String): String
    external fun getCoreVersion(): String
}
