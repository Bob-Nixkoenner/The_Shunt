package org.theshunt.app

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import org.theshunt.mobile.Engine
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * The defense watcher (Max Security level, switch off by default). On Android it
 * is a watcher, not a trap: no root, no decoy ports, no sniffing. The core
 * watches what the VPN sees anyway: DNS tunnelling, regular "beacon"
 * connections of one app, the first contact of an app with a new
 * destination, and destinations on the Feodo/SSLBL lists. It only reports;
 * nothing is blocked and nothing leaves the phone (events stay in memory, the
 * first-contact memory holds hashes in the app's private files).
 *
 * Not available on Android (no root, not allowed to apps): ARP/DHCP/router
 * checks, decoys, scan detection, firewall. Evil-twin and TLS checks are not
 * built (see docs/DEFENSE.md).
 */
object Defense {
    val CLASSES = listOf("unknown", "unsafe", "safe")

    /** Old identifiers (before 2026-11-12) to the new ones: public = unknown, trusted and managed = safe. */
    fun migrate(c: String) = when (c) {
        "public" -> "unknown"
        "trusted", "managed" -> "safe"
        else -> c
    }
    private const val MAX_AGE_MS = 12 * 3600 * 1000L

    fun dir(ctx: Context) = File(ctx.filesDir, "defense")

    /** The class of the network kind ("wifi", "mobile", ...); not rated = unknown. */
    fun classFor(s: Settings, link: String): String = s.netClasses[link]?.let { migrate(it) }?.takeIf { it in CLASSES } ?: "unknown"

    /**
     * The key the core keeps per network, only in memory: a hash of the kind of
     * network (or of a Wi-Fi name, should one ever be passed). Never the name itself.
     */
    fun netKey(link: String, ssid: String = ""): String =
        MessageDigest.getInstance("SHA-256").digest("$link/$ssid".toByteArray()).take(6).joinToString("") { "%02x".format(it) }

    /** Settings for the core: only the switch; the features that exist here are all on while it is. */
    fun configJson(s: Settings): String = JSONObject().put("enabled", s.defense).toString()

    fun apply(ctx: Context, e: Engine, s: Settings) {
        runCatching { e.defenseConfig(configJson(s)) }.onFailure { Log.w("Shunt", "defense config: ${it.message}") }
        network(e, s, VpnState.link)
    }

    fun network(e: Engine, s: Settings, link: String) {
        runCatching { e.defenseNetwork(netKey(link), classFor(s, link)) }
    }

    /**
     * Downloads the list files the core asks for (Feodo, SSLBL) like the filter
     * lists: by the app itself (outside its own VPN, so directly), a copy older than
     * 12 hours is fetched again, an old copy stays if that fails. Then the core reloads.
     */
    fun refreshLists(ctx: Context, e: Engine?) {
        e ?: return
        try {
            val srcs = JSONArray(e.defenseSources())
            if (srcs.length() == 0) return
            val d = dir(ctx).apply { mkdirs() }
            for (i in 0 until srcs.length()) {
                val o = srcs.getJSONObject(i)
                val f = File(d, File(o.getString("file")).name)
                if (f.exists() && System.currentTimeMillis() - f.lastModified() < MAX_AGE_MS) continue
                try {
                    val tmp = File(f.path + ".part")
                    val c = URL(o.getString("url")).openConnection() as HttpURLConnection
                    c.connectTimeout = 10_000
                    c.readTimeout = 30_000
                    if (c.responseCode != 200) throw IllegalStateException("HTTP ${c.responseCode}")
                    c.inputStream.use { input -> tmp.outputStream().use { input.copyTo(it) } }
                    tmp.renameTo(f)
                } catch (ex: Exception) {
                    Log.w("Shunt", "defense list ${o.optString("name")}: ${ex.message}")
                }
            }
            e.defenseReload()
        } catch (ex: Exception) {
            Log.w("Shunt", "defense lists: ${ex.message}")
        }
    }

    /** One event of the core. [detail] has the app's package name and a destination, never anything of the user's own network. */
    data class Event(val seq: Long, val time: Long, val kind: String, val severity: Int, val src: String, val port: Int, val detail: String, val trust: String = "")

    fun parseEvents(json: String): List<Event> {
        val a = JSONObject(json).optJSONArray("events") ?: return emptyList()
        return (0 until a.length()).map {
            val o = a.getJSONObject(it)
            Event(o.optLong("seq"), parseTime(o.optString("time")), o.optString("kind"), o.optInt("severity"), o.optString("src"), o.optInt("port"), o.optString("detail"), o.optString("trust"))
        }
    }

    private fun parseTime(s: String): Long = try {
        java.time.OffsetDateTime.parse(s).toInstant().toEpochMilli()
    } catch (e: Exception) {
        0L
    }

    /** "key=value key=value" of an event's detail. */
    fun fields(detail: String): Map<String, String> =
        detail.split(' ').filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }

    /** The line shown for an event (translated). */
    fun text(ev: Event): String {
        val f = fields(ev.detail)
        val dst = if (ev.src.isNotEmpty()) ev.src + (if (ev.port > 0) ":${ev.port}" else "") else ""
        return when (ev.kind) {
            "reputation" -> T("{app} contacted {dst}, an address on the list {list}.", "app" to (f["app"] ?: "?"), "dst" to dst, "list" to (f["list"] ?: "?"))
            "first_seen" -> T("{app} contacted a new destination: {target}.", "app" to (f["app"] ?: "?"), "target" to (f["target"] ?: dst))
            "beacon" -> T("{app} connects to {dst} at regular intervals ({interval}).", "app" to (f["app"] ?: "?"), "dst" to dst, "interval" to (f["interval"] ?: "?"))
            "dns_tunnel" -> T("Unusual DNS queries for {domain} (possible DNS tunnel).", "domain" to (f["domain"] ?: "?"))
            "net_enter" -> T("Network joined, class {class}.", "class" to T(classLabel(migrate(f["class"] ?: "unknown"))))
            "bait" -> T("Bait credentials used") + (if (dst.isNotEmpty()) " $dst" else "")
            "automated_chain" -> T("Automated attack") + (if (dst.isNotEmpty()) " $dst" else "")
            else -> ev.kind
        }
    }

    fun classLabel(c: String) = when (c) {
        "safe" -> "Safe"
        "unsafe" -> "Unsafe"
        else -> "Unclear"
    }

    /** Thermometer reading of a level: label for the tile. */
    fun levelLabel(level: String) = when (level) {
        "noticed" -> "Noticed"
        "hot" -> "Elevated"
        "attack" -> "Attack"
        else -> "Quiet"
    }
}
