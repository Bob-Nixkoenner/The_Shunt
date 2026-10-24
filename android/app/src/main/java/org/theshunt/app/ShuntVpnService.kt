package org.theshunt.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.theshunt.mobile.Engine
import org.theshunt.mobile.Mobile
import org.theshunt.mobile.Platform
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors

/** What the UI shows: running or not, last error. */
object VpnState {
    val running = MutableStateFlow(false)
    val error = MutableStateFlow<String?>(null)
    @Volatile var engine: Engine? = null
    /** A start reached the service in this process (it may still be connecting). */
    @Volatile var startRequested = false
    /** Android's own kill switch: always-on VPN with "block connections without VPN". */
    val alwaysOn = MutableStateFlow(false)
    val lockdown = MutableStateFlow(false)
    /** Android's "Private DNS" (DoT) is active: it bypasses the VPN's DNS. */
    val privateDns = MutableStateFlow(false)
    /** The running service, to ask it again: the user turns always-on on while it runs. */
    @Volatile var service: VpnService? = null

    /** Brings the status notification up to date (panic, pass, kill switch). */
    fun refreshNotification() {
        (service as? ShuntVpnService)?.notifyStatus()
    }

    /** Re-reads the kill switch (the UI calls this while it is visible). */
    fun refreshKillSwitch() {
        val s = service ?: return
        alwaysOn.value = s.isAlwaysOn
        lockdown.value = s.isLockdownEnabled
    }

    val isRunning: StateFlow<Boolean> get() = running
}

/**
 * One TUN for all apps; the Go core splits the traffic per app across the
 * tunnels (see mobile/mobile.go). The Shunt itself is excluded from its own
 * VPN, so the core's outgoing sockets (WireGuard, direct route) go out over
 * the real network without a loop.
 */
class ShuntVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            Watchdog.setWanted(this, false)
            VpnState.startRequested = false
            worker.execute { stopEngine() }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(startId) // not if a newer start came in meanwhile
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_PANIC) {
            VpnState.engine?.let { e ->
                val on = e.status().let { org.json.JSONObject(it).optJSONObject("override")?.optBoolean("panic") } ?: false
                e.setPanic(!on)
                notifyStatus()
            }
            return START_STICKY
        }
        // a foreground service with a status notification: Android does not
        // stop it to save memory, and the user sees that the VPN runs
        VpnState.startRequested = true
        goForeground("Starting…")
        // null intent: restarted by the system or always-on VPN. On the
        // worker: endpoint lookups and list downloads take a moment, and
        // start/stop must not overlap.
        worker.execute { startEngine() }
        return START_STICKY
    }

    private fun startEngine() {
        stopEngine()
        val settings = Store.load(this)
        try {
            val b = Builder()
                .setSession("The Shunt")
                .setMtu(1280)
                .addAddress("10.111.0.2", 24)
                .addAddress("fd11:5ee:bad:c0de::2", 64)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(Mobile.DNSAddr)
                .addDisallowedApplication(packageName)
            b.setBlocking(false)
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            // tell Android which real network carries the VPN, so apps see
            // whether it is Wi-Fi or (metered) mobile data
            cm.activeNetwork?.let { b.setUnderlyingNetworks(arrayOf(it)) }
            b.setMetered(false) // follows the underlying network's meteredness
            val pfd = b.establish() ?: throw IllegalStateException("VPN permission missing")
            tun = pfd
            runCatching { Mobile.setTimezone(java.util.TimeZone.getDefault().id) } // log times in local time
            VpnState.engine = Mobile.start(pfd.fd.toLong(), settings.coreJson(this), CorePlatform(cm))
            netCallback = NetWatch(cm).also { cm.registerDefaultNetworkCallback(it) }
            VpnState.error.value = null
            VpnState.running.value = true
            VpnState.service = this
            VpnState.refreshKillSwitch()
            notifyStatus()
            Watchdog.setWanted(this, true)
            watchdog.post(pushWatchdog)
            // filter lists: start with what is on disk, then refresh (also
            // without network the VPN must come up at once)
            if (Blocklists.refresh(this, settings.filterLists)) applyRules(this, Store.load(this))
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            VpnState.error.value = e.message ?: e.toString()
            VpnState.startRequested = false
            stopEngine()
            notifyStatus() // shows the error; the service may end now
            stopForeground(STOP_FOREGROUND_DETACH)
        }
    }

    /**
     * Follows the real default network (The Shunt is outside its own VPN,
     * so this is Wi-Fi or mobile data). Changes come in bursts – Wi-Fi up,
     * then validated, then addresses – so they are settled for a second
     * before WireGuard gets new sockets (Wi-Fi <-> mobile data).
     */
    private inner class NetWatch(private val cm: ConnectivityManager) : ConnectivityManager.NetworkCallback() {
        private val main = Handler(Looper.getMainLooper())
        private var current: Network? = null
        private var applied: Network? = null
        private var addrs: Set<String> = emptySet()
        private var appliedAddrs: Set<String> = emptySet()
        private var appliedLink: String? = null
        private val settle = Runnable {
            val n = current
            setUnderlyingNetworks(n?.let { arrayOf(it) })
            if (applied != null && n != null && (n != applied || addrs != appliedAddrs)) VpnState.engine?.networkChanged()
            if (n != null) { applied = n; appliedAddrs = addrs }
            // the kind of network for link:wifi / link:mobile routes (and network profiles)
            val link = linkOf(n?.let { cm.getNetworkCapabilities(it) })
            if (link != appliedLink) {
                VpnState.engine?.let { it.setNetwork(link, ""); appliedLink = link }
            }
            notifyStatus()
        }

        private fun linkOf(caps: NetworkCapabilities?): String = when {
            caps == null -> ""
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "mobile"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> ""
        }

        private fun later() {
            main.removeCallbacks(settle)
            main.postDelayed(settle, 1000)
        }

        override fun onAvailable(network: Network) {
            current = network
            if (applied == null) applied = network // the one the VPN started on
            later()
        }

        override fun onLost(network: Network) {
            if (network == current) { current = null; later() }
        }

        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            if (network != current) return
            VpnState.privateDns.value = lp.isPrivateDnsActive
            addrs = lp.linkAddresses.map { it.address.hostAddress ?: "" }.toSet()
            if (appliedAddrs.isEmpty() && applied == network) appliedAddrs = addrs
            later()
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (network == current) later() // e.g. metered changed: underlying networks again
        }

        fun stop() = main.removeCallbacks(settle)
    }

    private fun goForeground(text: String) {
        val n = notification(text)
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFY_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(NOTIFY_ID, n)
    }

    /** Updates the status notification: protected / panic / pass / off. */
    internal fun notifyStatus() {
        val e = VpnState.engine
        val ov = e?.status()?.let { org.json.JSONObject(it).optJSONObject("override") }
        val text = when {
            e == null -> VpnState.error.value?.let { "Error: $it" } ?: "Off"
            ov?.optBoolean("panic") == true -> "PANIC – everything blocked"
            (ov?.optLong("pass_left") ?: 0) > 0 -> "PASS – unprotected"
            !VpnState.lockdown.value -> "On – no kill switch (Android VPN settings)"
            else -> "Protected"
        }
        getSystemService(NotificationManager::class.java).notify(NOTIFY_ID, notification(text, if (e == null) 0 else activeTunnels(e)))
    }

    /** Tunnels that work: up and answering, or asleep (on demand, made on first use). */
    private fun activeTunnels(e: Engine): Int {
        val ts = runCatching { org.json.JSONObject(e.status()).optJSONArray("tunnels") }.getOrNull() ?: return 0
        var n = 0
        for (i in 0 until ts.length()) {
            val t = ts.getJSONObject(i)
            val state = t.optJSONObject("health")?.optString("state")
            if (t.optBoolean("idle") || (t.optBoolean("up") && (state == "ok" || state == "idle"))) n++
        }
        return n
    }

    private fun notification(text: String, active: Int = 0): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW))
        }
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), flags)
        val panic = PendingIntent.getService(this, 1, Intent(this, ShuntVpnService::class.java).setAction(ACTION_PANIC), flags)
        val stop = PendingIntent.getService(this, 2, Intent(this, ShuntVpnService::class.java).setAction(ACTION_STOP), flags)
        return Notification.Builder(this, CHANNEL)
            .apply { if (active > 0) setSmallIcon(StatusIcon.create(active)) else setSmallIcon(R.drawable.ic_notify) }
            .setContentTitle("The Shunt")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setShowWhen(false)
            .addAction(Notification.Action.Builder(null, "Panic", panic).build())
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    /** Keeps the watchdog job in the future while the VPN runs. */
    private val watchdog = Handler(Looper.getMainLooper())
    private var pushes = 0L
    private val pushWatchdog = object : Runnable {
        override fun run() {
            Watchdog.push(this@ShuntVpnService)
            // the tunnel count in the status bar icon: tunnels come and go without an event of ours
            if (++pushes % (NOTIFY_REFRESH_MS / Watchdog.PUSH_MS) == 0L) notifyStatus()
            watchdog.postDelayed(this, Watchdog.PUSH_MS)
        }
    }

    private fun stopEngine() {
        watchdog.removeCallbacks(pushWatchdog)
        (netCallback as? NetWatch)?.stop()
        netCallback?.let {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
        }
        netCallback = null
        VpnState.engine?.stop()
        VpnState.engine = null
        VpnState.service = null
        tun?.close()
        tun = null
        VpnState.running.value = false
    }

    override fun onRevoke() { // another VPN took over, or the user switched it off
        Watchdog.setWanted(this, false)
        VpnState.startRequested = false
        worker.execute { stopEngine() }
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onRevoke()
    }

    override fun onDestroy() {
        worker.execute { stopEngine() }
        super.onDestroy()
    }

    private class CorePlatform(private val cm: ConnectivityManager) : Platform {
        override fun ownerUid(proto: Long, srcIP: String, srcPort: Long, dstIP: String, dstPort: Long): Long = try {
            cm.getConnectionOwnerUid(
                proto.toInt(),
                InetSocketAddress(InetAddress.getByName(srcIP), srcPort.toInt()),
                InetSocketAddress(InetAddress.getByName(dstIP), dstPort.toInt()),
            ).toLong()
        } catch (e: Exception) {
            -1
        }

        override fun log(msg: String) {
            Log.i(TAG, msg)
        }
    }

    companion object {
        private const val TAG = "Shunt"

        /** Start and stop run one after the other, off the main thread. */
        private val worker = Executors.newSingleThreadExecutor()

        // One VPN per process, whichever service instance started it; only
        // touched on the worker.
        private var tun: ParcelFileDescriptor? = null
        private var netCallback: ConnectivityManager.NetworkCallback? = null
        const val ACTION_STOP = "org.theshunt.app.STOP"
        const val ACTION_PANIC = "org.theshunt.app.PANIC"
        private const val CHANNEL = "status"
        const val NOTIFY_ID = 1
        const val NOTIFY_REFRESH_MS = 10 * 60_000L

        fun start(ctx: Context) = ctx.startService(Intent(ctx, ShuntVpnService::class.java))
        fun stop(ctx: Context) = ctx.startService(Intent(ctx, ShuntVpnService::class.java).setAction(ACTION_STOP))

        /** Applies changed app rules to the running core without dropping the VPN. */
        fun applyRules(ctx: Context, s: Settings): String? {
            val e = VpnState.engine ?: return null
            return try {
                e.setRules(s.coreJson(ctx)); null
            } catch (ex: Exception) {
                ex.message
            }
        }
    }
}
