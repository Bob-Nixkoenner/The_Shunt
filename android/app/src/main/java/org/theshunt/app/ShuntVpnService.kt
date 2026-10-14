package org.theshunt.app

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
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
    /** Android's own kill switch: always-on VPN with "block connections without VPN". */
    val alwaysOn = MutableStateFlow(false)
    val lockdown = MutableStateFlow(false)
    /** The running service, to ask it again: the user turns always-on on while it runs. */
    @Volatile var service: VpnService? = null

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
            worker.execute { stopEngine() }
            stopSelf(startId) // not if a newer start came in meanwhile
            return START_NOT_STICKY
        }
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
            val pfd = b.establish() ?: throw IllegalStateException("VPN permission missing")
            tun = pfd
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            runCatching { Mobile.setTimezone(java.util.TimeZone.getDefault().id) } // log times in local time
            VpnState.engine = Mobile.start(pfd.fd.toLong(), settings.coreJson(this), CorePlatform(cm))
            // Wi-Fi <-> mobile data: WireGuard needs new sockets on the new network
            netCallback = object : ConnectivityManager.NetworkCallback() {
                private var current: Network? = null
                override fun onAvailable(network: Network) {
                    if (current != null && current != network) VpnState.engine?.networkChanged()
                    current = network
                }
            }.also { cm.registerDefaultNetworkCallback(it) }
            VpnState.error.value = null
            VpnState.running.value = true
            VpnState.service = this
            VpnState.refreshKillSwitch()
            // filter lists: start with what is on disk, then refresh (also
            // without network the VPN must come up at once)
            if (Blocklists.refresh(this, settings.filterLists)) applyRules(this, Store.load(this))
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            VpnState.error.value = e.message ?: e.toString()
            stopEngine()
        }
    }

    private fun stopEngine() {
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
        worker.execute { stopEngine() }
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
