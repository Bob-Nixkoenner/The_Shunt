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

/** What the UI shows: running or not, last error. */
object VpnState {
    val running = MutableStateFlow(false)
    val error = MutableStateFlow<String?>(null)
    @Volatile var engine: Engine? = null

    val isRunning: StateFlow<Boolean> get() = running
}

/**
 * One TUN for all apps; the Go core splits the traffic per app across the
 * tunnels (see mobile/mobile.go). The Shunt itself is excluded from its own
 * VPN, so the core's outgoing sockets (WireGuard, direct route) go out over
 * the real network without a loop.
 */
class ShuntVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            synchronized(this) { stopEngine() }
            stopSelf()
            return START_NOT_STICKY
        }
        // null intent: restarted by the system or always-on VPN. Off the main
        // thread: list downloads and endpoint lookups take a moment.
        Thread { synchronized(this) { startEngine() } }.start()
        return START_STICKY
    }

    private fun startEngine() {
        stopEngine()
        val settings = Store.load(this)
        Blocklists.refresh(this, settings.filterLists)
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
        tun?.close()
        tun = null
        VpnState.running.value = false
    }

    override fun onRevoke() { // another VPN took over, or the user switched it off
        stopEngine()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopEngine()
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
