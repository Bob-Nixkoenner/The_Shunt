package org.theshunt.app

import android.app.Application
import android.os.Handler
import android.os.Looper

/** Runs whenever the process starts: after a crash the VPN comes back at once (see [Watchdog]). */
class ShuntApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // a bit later: on boot or for always-on, Android starts the VPN itself
        Handler(Looper.getMainLooper()).postDelayed({ Watchdog.restartIfNeeded(this, "process start") }, 3000)
    }
}
