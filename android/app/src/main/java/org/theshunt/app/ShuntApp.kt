package org.theshunt.app

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import com.journeyapps.barcodescanner.CaptureActivity

/** Runs whenever the process starts: after a crash the VPN comes back at once (see [Watchdog]). */
class ShuntApp : Application() {
    override fun onCreate() {
        super.onCreate()
        I18n.init(this)
        // the QR scanner shows a tunnel's private key: keep it out of
        // screenshots, screen recordings and the recent-apps preview
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(a: Activity, b: Bundle?) {
                if (a is CaptureActivity) a.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            override fun onActivityStarted(a: Activity) {}
            override fun onActivityResumed(a: Activity) {}
            override fun onActivityPaused(a: Activity) {}
            override fun onActivityStopped(a: Activity) {}
            override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
            override fun onActivityDestroyed(a: Activity) {}
        })
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
