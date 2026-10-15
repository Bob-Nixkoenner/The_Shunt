package org.theshunt.app

import android.app.NotificationManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.net.VpnService
import android.util.Log

/**
 * Brings the VPN back after the app process died (crash in the Go core,
 * killed). Android restarts an always-on VPN only on boot and package
 * update, not after a crash: the phone then stays offline (lockdown) or
 * unprotected until the app is opened by hand.
 *
 * Dead man's switch: while the VPN runs, the service keeps pushing a job
 * [DELAY_MS] into the future. When the process dies, nobody pushes any more,
 * the job fires and starts the VPN again (after ~30–45 s). A process that comes back for
 * another reason (the panic tile) checks at once in [ShuntApp].
 */
object Watchdog {
    private const val TAG = "Shunt"
    private const val JOB_ID = 1
    private const val PREFS = "watchdog"
    private const val KEY_WANTED = "vpn_wanted"
    const val DELAY_MS = 30_000L
    /** How often the running service pushes the job back. */
    const val PUSH_MS = 10_000L

    /** Whether the user wants the VPN on (set on start, cleared on stop/revoke). */
    fun wanted(ctx: Context) = prefs(ctx).getBoolean(KEY_WANTED, false)

    fun setWanted(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_WANTED, on).apply()
        if (on) push(ctx) else jobs(ctx).cancel(JOB_ID)
    }

    /** (Re)schedules the job [DELAY_MS] from now; replaces the pending one. */
    fun push(ctx: Context) {
        val job = JobInfo.Builder(JOB_ID, ComponentName(ctx, WatchdogJob::class.java))
            .setMinimumLatency(DELAY_MS)
            .setOverrideDeadline(DELAY_MS + 15_000)
            .setPersisted(false)
            .build()
        jobs(ctx).schedule(job)
    }

    /**
     * Starts the VPN if it should run but does not: wanted, permission still
     * granted and no engine in this process. Returns whether it started it.
     */
    fun restartIfNeeded(ctx: Context, why: String): Boolean {
        if (VpnState.engine != null || VpnState.startRequested || !wanted(ctx)) return false
        if (VpnService.prepare(ctx) != null) { // permission gone (other VPN app took over)
            setWanted(ctx, false)
            return false
        }
        Log.w(TAG, "watchdog: VPN should run but does not ($why), restarting")
        // the dead process' status notification may still be there
        ctx.getSystemService(NotificationManager::class.java).cancel(ShuntVpnService.NOTIFY_ID)
        return try {
            ShuntVpnService.start(ctx); true
        } catch (e: Exception) { // background start not allowed: the job tries again
            Log.e(TAG, "watchdog: restart failed", e)
            push(ctx)
            false
        }
    }

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun jobs(ctx: Context) = ctx.getSystemService(JobScheduler::class.java)
}

/** The job behind [Watchdog]: only runs when the process was dead for a minute. */
class WatchdogJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        if (!Watchdog.restartIfNeeded(this, "job") && VpnState.engine != null) Watchdog.push(this)
        return false
    }

    override fun onStopJob(params: JobParameters) = false
}
