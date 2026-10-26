package org.theshunt.app

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.Looper

/** Runs whenever the process starts: after a crash the VPN comes back at once (see [Watchdog]). */
class ShuntApp : Application() {
    override fun onCreate() {
        super.onCreate()
        I18n.init(this)
        // the app list of the Apps tab is cached: forget it when apps come or go
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) = AppCache.clear()
        }, IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        })
        // a bit later: on boot or for always-on, Android starts the VPN itself
        Handler(Looper.getMainLooper()).postDelayed({ Watchdog.restartIfNeeded(this, "process start") }, 3000)
    }
}
