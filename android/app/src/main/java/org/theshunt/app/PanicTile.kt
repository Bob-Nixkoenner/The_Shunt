package org.theshunt.app

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Quick settings tile: panic on/off without opening the app. */
class PanicTile : TileService() {
    private var panic = false

    override fun onStartListening() = refresh()

    override fun onClick() {
        val e = VpnState.engine ?: return refresh()
        panic = !panic
        e.setPanic(panic)
        refresh()
    }

    private fun refresh() {
        val e = VpnState.engine
        panic = e?.status()?.let { org.json.JSONObject(it).optJSONObject("override")?.optBoolean("panic") } ?: false
        qsTile?.apply {
            state = when {
                e == null -> Tile.STATE_UNAVAILABLE
                panic -> Tile.STATE_ACTIVE
                else -> Tile.STATE_INACTIVE
            }
            subtitle = if (e == null) T("VPN off") else if (panic) T("everything blocked") else T("off")
            updateTile()
        }
    }
}
