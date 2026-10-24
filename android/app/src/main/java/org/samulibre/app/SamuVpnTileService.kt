package org.samulibre.app

import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

/**
 * Mosaico de Ajustes Rápidos (Quick Settings Tile) de SamuLibre (v2.00.2).
 *
 * Permite al usuario conectar y desconectar la VPN de SamuLibre con un solo toque
 * desde la persiana superior de Android en cualquier momento (estilo Bitdefender / Cloudflare WARP).
 */
@RequiresApi(Build.VERSION_CODES.N)
class SamuVpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        val tile = qsTile ?: return

        if (tile.state == Tile.STATE_ACTIVE) {
            // Desconectar VPN
            val stopIntent = Intent(this, SamuVpnService::class.java).apply {
                action = SamuVpnService.ACTION_STOP
            }
            startService(stopIntent)
            tile.state = Tile.STATE_INACTIVE
            tile.label = "SamuLibre VPN"
            tile.updateTile()
        } else {
            // Conectar VPN inmediata con Smart Proxy
            val startIntent = Intent(this, SamuVpnService::class.java).apply {
                action = SamuVpnService.ACTION_START_PROXY_VPN
                putExtra(SamuVpnService.EXTRA_PROXY_PORT, SamuSmartProxyServer.DEFAULT_PORT)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent)
            } else {
                startService(startIntent)
            }
            tile.state = Tile.STATE_ACTIVE
            tile.label = "VPN Protegida"
            tile.updateTile()
        }
    }

    private fun updateTileState() {
        val tile = qsTile ?: return
        val isVpnActive = SamuVpnService.instance != null
        tile.state = if (isVpnActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.icon = Icon.createWithResource(this, R.drawable.ic_stat_samulibre_shield)
        tile.label = if (isVpnActive) "VPN Protegida" else "SamuLibre VPN"
        tile.contentDescription = "Control Rápido de VPN SamuLibre"
        tile.updateTile()
    }
}
