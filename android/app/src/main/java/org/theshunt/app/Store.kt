package org.theshunt.app

import android.content.Context
import android.content.pm.PackageManager
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * One imported tunnel: a WireGuard wg-quick file or a cleaned .ovpn file
 * (type "openvpn", with user/pass for auth-user-pass), as text.
 */
data class Tunnel(
    val name: String,
    val conf: String,
    val type: String = WIREGUARD,
    val user: String = "",
    val pass: String = "",
    /** Name of the WireGuard tunnel that carries this one (multi-hop), "" = direct. */
    val via: String = "",
) {
    val isOpenVPN get() = type == OPENVPN
    /** A Tor tunnel: TCP and names go to a Tor client on this phone (Orbot), see conf. */
    val isTor get() = type == TOR

    fun toJson(): JSONObject = JSONObject().put("name", name).put("conf", conf).put("via", via).apply {
        if (isOpenVPN) put("type", OPENVPN).put("user", user).put("pass", pass)
        if (isTor) put("type", TOR)
    }

    companion object {
        const val WIREGUARD = "wireguard"
        const val OPENVPN = "openvpn"
        const val TOR = "tor"

        /** Orbot (the Tor app of the Guardian Project): SOCKS 9050; names go through SOCKS (Orbot's DNSPort is random). */
        const val TOR_DEFAULT_CONF = "socks = 127.0.0.1:9050\n"
        /** The Tor the app brings along (libtor.so). */
        const val TOR_BUILTIN_CONF = "client = builtin\n"
        const val ORBOT = "org.torproject.android"
    }
}

/**
 * The app's configuration: tunnels, default route and one route per app
 * (by package name). Kept as JSON in the app's private files.
 * Routes are named as in shunt.toml: "direct", "block", "tunnel:<name>".
 */
/** A network profile: on this kind of network (wifi | mobile) apps without a rule take [route]. */
data class NetProfile(val link: String, val route: String) {
    fun toJson(): JSONObject = JSONObject().put("name", link).put("link", link).put("default", route)

    companion object {
        val LINKS = listOf("wifi", "mobile")
    }
}

data class Settings(
    val tunnels: List<Tunnel> = emptyList(),
    val defaultRoute: String = "block",
    val apps: Map<String, String> = emptyMap(),
    val directDns: String = "1.1.1.1",
    /** DNS filter lists (Blocklists.ALL names); empty = filter off. */
    val filterLists: List<String> = Blocklists.DEFAULT,
    /** Apps (package names) whose DNS is not filtered. */
    val unfiltered: Set<String> = emptySet(),
    /** Tunnels nobody uses are closed (battery) and made again on the first connection. */
    val onDemand: Boolean = true,
    /** DNS servers asked after the route's own one when that does not answer. */
    val dnsServers: List<String> = DEFAULT_DNS,
    /** Leave the DNS of the tunnel files out (Tailscale's resolver stays). */
    val ignoreTunnelDns: Boolean = false,
    /** Another default route on Wi-Fi or mobile data (network profiles of the core). */
    val networks: List<NetProfile> = emptyList(),
    /** Emergency: every app goes through the Tor tunnel (routes are kept, not used). */
    val torAll: Boolean = false,
    /** What the app shows (Settings tab): Simple, Pro or Opsec, see Levels.kt. */
    val level: Level = Level.Simple,
    /** The strict check (Opsec): findings on the Status tab, see StrictCheck. */
    val strictCheck: Boolean = false,
    /** What Opsec switched on, with the value from before (offered back when leaving Opsec). */
    val opsecUndo: Map<String, Boolean> = emptyMap(),
) {
    /** Whether a part of the app shows in the current level (Levels.TABLE). */
    fun shows(key: String) = Levels.shows(key, level)

    /** link:<kind> = direct, but only over that kind of network (blocked on the other). */
    fun routes(): List<String> = listOf("direct", "block") + tunnels.map { "tunnel:${it.name}" } + listOf("link:wifi", "link:mobile")

    fun toJson(): JSONObject = JSONObject().apply {
        put("tunnels", JSONArray(tunnels.map { it.toJson() }))
        put("default", defaultRoute)
        put("apps", JSONObject(apps))
        put("direct_dns", directDns)
        put("filter_lists", JSONArray(filterLists))
        put("unfiltered_apps", JSONArray(unfiltered.toList()))
        put("on_demand", onDemand)
        put("dns_servers", JSONArray(dnsServers))
        put("ignore_tunnel_dns", ignoreTunnelDns)
        put("networks", JSONArray(networks.map { it.toJson() }))
        put("tor_all", torAll)
        put("level", level.key)
        // older versions read "pro" (Normal/Pro): going back keeps the choice
        put("pro", level != Level.Simple)
        put("strict_check", strictCheck)
        put("opsec_undo", JSONObject(opsecUndo))
    }

    /** The core's config: app rules by UID instead of package name. */
    fun coreJson(ctx: Context): String {
        val pm = ctx.packageManager
        fun uid(pkg: String): Int? = try {
            pm.getApplicationInfo(pkg, 0).uid
        } catch (e: PackageManager.NameNotFoundException) {
            null // uninstalled
        }
        val uids = JSONObject()
        for ((pkg, route) in apps) uid(pkg)?.let { uids.put(it.toString(), route) }
        val lists = JSONArray()
        for (name in filterLists) {
            val f = Blocklists.file(ctx, name)
            if (f.exists()) lists.put(JSONObject().put("name", name).put("path", f.path))
        }
        val tor = tunnels.firstOrNull { it.isTor }
        if (torAll && tor != null) {
            // everything on the Tor tunnel: the default, every app, no per-network profile
            val route = "tunnel:${tor.name}"
            for (k in uids.keys().asSequence().toList()) uids.put(k, route)
            return toJson().put("default", route).put("networks", JSONArray())
                .put("apps", uids)
                .put("blocklists", lists)
                .put("unfiltered", JSONArray(unfiltered.mapNotNull { uid(it)?.toString() }))
                .put("stats_path", java.io.File(ctx.filesDir, "stats.json").path)
                .put("block_doh", true)
                .apply { engineExes(ctx) }
                .toString()
        }
        return toJson()
            .put("apps", uids)
            .put("blocklists", lists)
            .put("unfiltered", JSONArray(unfiltered.mapNotNull { uid(it)?.toString() }))
            .put("stats_path", java.io.File(ctx.filesDir, "stats.json").path)
            // as on the desktop: public DoH endpoints and Firefox's canary get NXDOMAIN,
            // so browsers stay on our DNS (route + filter)
            .put("block_doh", true)
            .apply { engineExes(ctx) }
            .toString()
    }

    /** GeoIP tables for the built-in Tor (assets tor/geoip*): into files/tor/, where the
     *  engine looks; again after an app update. Without them Tor shows no exit country. */
    private fun copyGeoIP(ctx: Context) {
        val dir = File(ctx.filesDir, "tor").apply { mkdirs() }
        val updated = ctx.packageManager.getPackageInfo(ctx.packageName, 0).lastUpdateTime
        for (n in listOf("geoip", "geoip6")) {
            val f = File(dir, n)
            if (f.exists() && f.lastModified() >= updated) continue
            runCatching {
                val tmp = File(dir, "$n.tmp")
                ctx.assets.open("tor/$n").use { i -> tmp.outputStream().use { i.copyTo(it) } }
                tmp.renameTo(f)
            }
        }
    }

    /** The programs the app brings (Android runs programs only from lib/<abi>/lib….so). */
    private fun JSONObject.engineExes(ctx: Context) {
        val dir = ctx.applicationInfo.nativeLibraryDir
        val ovpn = File(dir, "libopenvpn.so")
        if (ovpn.exists()) put("openvpn", ovpn.path).put("work_dir", ctx.filesDir.path)
        // the Tor program of tor-android (libtor.so), for Tor tunnels without Orbot
        val tor = File(dir, "libtor.so")
        if (tor.exists()) put("tor_exe", tor.path).put("work_dir", ctx.filesDir.path)
        if (tor.exists()) copyGeoIP(ctx)
        // lyrebird: the bridge transports (obfs4, snowflake, meek, webtunnel)
        val pt = File(dir, "liblyrebird.so")
        if (pt.exists()) put("pt_exe", pt.path)
    }

    companion object {
        fun fromJson(o: JSONObject): Settings {
            val ts = o.optJSONArray("tunnels") ?: JSONArray()
            val apps = o.optJSONObject("apps") ?: JSONObject()
            fun strings(key: String): List<String>? = o.optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } }
            return Settings(
                tunnels = (0 until ts.length()).map {
                    val t = ts.getJSONObject(it)
                    Tunnel(t.getString("name"), t.getString("conf"), t.optString("type", Tunnel.WIREGUARD), t.optString("user"), t.optString("pass"), t.optString("via"))
                },
                defaultRoute = o.optString("default", "block"),
                apps = apps.keys().asSequence().associateWith { apps.getString(it) },
                directDns = o.optString("direct_dns", "1.1.1.1"),
                filterLists = strings("filter_lists")?.filter { it in Blocklists.ALL } ?: Blocklists.DEFAULT,
                unfiltered = strings("unfiltered_apps")?.toSet() ?: emptySet(),
                onDemand = o.optBoolean("on_demand", true),
                dnsServers = strings("dns_servers")?.filter { isDnsAddress(it) } ?: DEFAULT_DNS,
                ignoreTunnelDns = o.optBoolean("ignore_tunnel_dns", false),
                torAll = o.optBoolean("tor_all", false),
                level = Level.from(o.optString("level").ifEmpty { null }, if (o.has("pro")) o.optBoolean("pro") else null),
                strictCheck = o.optBoolean("strict_check", false),
                opsecUndo = o.optJSONObject("opsec_undo")?.let { u -> u.keys().asSequence().associateWith { u.optBoolean(it) } } ?: emptyMap(),
                networks = o.optJSONArray("networks")?.let { a ->
                    (0 until a.length()).map { a.getJSONObject(it) }.filter { it.optString("link") in NetProfile.LINKS }
                        .map { NetProfile(it.getString("link"), it.optString("default", "block")) }
                } ?: emptyList(),
            )
        }

        /** The public resolvers offered by default (Cloudflare, Google). */
        val DEFAULT_DNS = listOf("1.1.1.1", "8.8.8.8")

        /** The core refuses anything but an IP address (at most 8 of them). */
        fun isDnsAddress(s: String) = android.net.InetAddresses.isNumericAddress(s)
        const val MAX_DNS = 8
    }
}

object Store {
    private const val FILE = "settings.json"

    // AtomicFile: the VPN service may read while the UI writes; a torn file
    // would start the VPN with the defaults (everything blocked, no tunnels).
    private fun file(ctx: Context) = AtomicFile(File(ctx.filesDir, FILE))

    fun load(ctx: Context): Settings = try {
        Settings.fromJson(JSONObject(String(file(ctx).readFully())))
    } catch (e: Exception) {
        Settings()
    }

    @Synchronized
    fun save(ctx: Context, s: Settings) {
        val f = file(ctx)
        val out = f.startWrite()
        try {
            out.write(s.toJson().toString(2).toByteArray())
            f.finishWrite(out)
        } catch (e: Exception) {
            f.failWrite(out)
            throw e
        }
    }

    /**
     * Gives a tunnel a new name and rewrites every route that names it (default,
     * apps, OpenVPN tunnels going through it). The traffic counts follow (renameStats).
     */
    fun rename(s: Settings, from: String, to: String): Settings {
        val old = "tunnel:$from"
        val new = "tunnel:$to"
        fun r(route: String) = if (route == old) new else route
        return s.copy(
            tunnels = s.tunnels.map { t -> (if (t.name == from) t.copy(name = to) else t).let { if (it.via == from) it.copy(via = to) else it } },
            defaultRoute = r(s.defaultRoute),
            apps = s.apps.mapValues { (_, route) -> r(route) },
            networks = s.networks.map { it.copy(route = r(it.route)) },
        )
    }

    /**
     * The statistics file keeps counts under the tunnel's name; they move to the new name.
     * Only while the VPN is off: the running core holds the file's contents in memory.
     */
    fun renameStats(ctx: Context, from: String, to: String) {
        val f = File(ctx.filesDir, "stats.json")
        if (!f.exists()) return
        try {
            val o = JSONObject(f.readText())
            fun move(m: JSONObject?) { if (m != null && m.has(from)) { m.put(to, m.get(from)); m.remove(from) } }
            move(o.optJSONObject("since"))
            move(o.optJSONObject("months"))
            o.optJSONArray("series")?.let { a -> for (i in 0 until a.length()) move(a.getJSONObject(i).optJSONObject("tun")) }
            f.writeText(o.toString())
        } catch (e: Exception) {
            android.util.Log.w("Shunt", "rename stats: ${e.message}")
        }
    }

    /** Turns a file name or QR import into a tunnel name like on the desktop: a-z 0-9 -, max. 10. */
    fun tunnelName(raw: String, taken: Collection<String>): String {
        var base = raw.substringBeforeLast(".conf").substringBeforeLast(".ovpn").lowercase().replace('_', '-')
            .filter { it in 'a'..'z' || it in '0'..'9' || it == '-' }.trimStart('-').take(10)
        if (base.isEmpty()) base = "vpn"
        var name = base
        var i = 2
        while (name in taken) name = base.take(8) + i++
        return name
    }
}
