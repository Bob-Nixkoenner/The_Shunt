package org.theshunt.app

import android.content.Context
import android.content.pm.PackageManager
import android.os.UserManager
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile

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
    /** Ports accepted from the tunnel and handed to this phone's apps ("tcp/1716"), empty = none. */
    val inbound: List<String> = emptyList(),
    /**
     * Set only when the sealed secret (conf, user, pass) could not be opened on this
     * device (key store key gone, e.g. after moving to another phone): the value as it
     * was stored, kept unchanged on every save. conf is empty then; see [locked].
     */
    val sealed: String = "",
) {
    /** The tunnel's keys cannot be read here: the core never gets it, its routes block. */
    val locked get() = sealed.isNotEmpty()

    val isOpenVPN get() = type == OPENVPN
    /** A Tor tunnel: TCP and names go to a Tor client on this phone (Orbot), see conf. */
    val isTor get() = type == TOR

    fun toJson(): JSONObject = JSONObject().put("name", name).put("conf", conf).put("via", via).apply {
        if (inbound.isNotEmpty()) put("inbound", JSONArray(inbound))
        if (isOpenVPN) put("type", OPENVPN).put("user", user).put("pass", pass)
        if (isTor) put("type", TOR)
    }

    /** The secret part, sealed by [Vault] in settings.json: the file (keys, bridges), user and password. */
    fun secretJson(): String = JSONObject().put("conf", conf).put("user", user).put("pass", pass).toString()

    /** As stored in settings.json: everything but [secretJson] in clear, that one sealed. */
    fun toStoreJson(v: Vault): JSONObject = JSONObject().put("name", name).put("via", via).apply {
        if (inbound.isNotEmpty()) put("inbound", JSONArray(inbound))
        if (isOpenVPN) put("type", OPENVPN)
        if (isTor) put("type", TOR)
        put("secret", if (locked) sealed else v.seal(secretJson()))
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

        /**
         * A tunnel from settings.json: new files hold "secret" (sealed), older ones
         * "conf"/"user"/"pass" in clear (moved into "secret" by Store.load).
         * A secret that does not open gives a locked tunnel, never an exception.
         */
        fun fromStoreJson(t: JSONObject, v: Vault?): Tunnel {
            val base = Tunnel(t.getString("name"), "", t.optString("type", WIREGUARD), via = t.optString("via"),
                inbound = t.optJSONArray("inbound")?.let { a -> (0 until a.length()).map { i -> a.getString(i) } } ?: emptyList())
            val secret = t.optString("secret")
            if (secret.isEmpty()) return base.copy(conf = t.getString("conf"), user = t.optString("user"), pass = t.optString("pass"))
            val o = v?.open(secret)?.let { runCatching { JSONObject(it) }.getOrNull() }
                ?: return base.copy(sealed = secret)
            return base.copy(conf = o.optString("conf"), user = o.optString("user"), pass = o.optString("pass"))
        }
    }
}

/**
 * The app's configuration: tunnels, default route and one route per app
 * (by package name). Kept as JSON in the app's private files.
 * Routes are named as in shunt.toml: "direct", "block", "tunnel:<name>".
 */
/**
 * A network profile: on this kind of network (wifi | mobile) apps without a rule take [route].
 * [wifi] set: only on the one Wi-Fi with this id (Defense.wifiId, a hash of its name, never the
 * name); the core gets the id as the network's "ssid" and compares it with what the app passes.
 */
data class NetProfile(val link: String, val route: String, val wifi: String = "", val lists: List<String>? = null) {
    /** As stored; [lists] (DNS filter list names, null = as everywhere) become paths only in Settings.coreJson. */
    fun toJson(): JSONObject = JSONObject().put("name", if (wifi.isEmpty()) link else "wifi-$wifi").put("link", link).put("default", route)
        .apply { if (wifi.isNotEmpty()) put("ssid", JSONArray(listOf(wifi))) }
        .apply { lists?.let { put("lists", JSONArray(it)) } }

    companion object {
        val LINKS = listOf("wifi", "mobile")

        /** Reads one profile as written by [toJson]; a "ssid" that is no Wi-Fi id is dropped. */
        fun fromJson(o: JSONObject) = NetProfile(o.getString("link"), o.optString("default", "block"),
            o.optJSONArray("ssid")?.optString(0).orEmpty().takeIf { Defense.isWifiId(it) }.orEmpty(),
            o.optJSONArray("lists")?.let { a -> (0 until a.length()).map { a.optString(it) }.filter { Blocklists.known(it) } })
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
    /** The defense watcher (Max Security): off by default, see Defense.kt. */
    val defense: Boolean = false,
    /** Network class per kind of network ("wifi", "mobile"): unknown, unsafe or safe; not rated = unknown. */
    val netClasses: Map<String, String> = emptyMap(),
    /** Warnings the user hid on the Status tab (see HiddenWarnings); stored here only, never given to the core. */
    val hiddenWarnings: List<HiddenWarning> = emptyList(),
    /** Mullvad logins (secrets sealed in the file) and the server of each Mullvad tunnel, see Mullvad.kt; never given to the core. */
    val mullvadLogins: List<MullvadLogin> = emptyList(),
    val mullvadExits: List<MullvadExit> = emptyList(),
    /** Names the DNS filter never blocks (Pro): one entry per line, as in a filter list ("||example.com^", "example.com", "@@||example.com^"). */
    val allowText: String = "",
) {
    /** Whether a part of the app shows in the current level (Levels.TABLE). */
    fun shows(key: String) = Levels.shows(key, level)

    /** Every DNS filter list in use: everywhere and on single Wi-Fi networks (to download). */
    fun allFilterLists(): List<String> = (filterLists + networks.flatMap { it.lists.orEmpty() }).distinct()

    private fun listsJson(ctx: Context, names: List<String>) = JSONArray().apply {
        for (name in names) {
            val f = Blocklists.file(ctx, name)
            if (f.exists()) put(JSONObject().put("name", name).put("path", f.path))
        }
    }

    /**
     * The network profiles for the core: one Wi-Fi's before the one for all Wi-Fi networks
     * (the core takes the first that fits), its route "" = the Wi-Fi row's, its own filter
     * lists with their files.
     */
    private fun coreNetworks(ctx: Context): JSONArray {
        val wifiRow = networks.find { it.link == "wifi" && it.wifi.isEmpty() }?.route.orEmpty()
        return JSONArray(networks.sortedBy { it.wifi.isEmpty() }.map { p ->
            p.toJson().apply {
                remove("lists")
                if (p.wifi.isNotEmpty() && p.route.isEmpty()) put("default", wifiRow)
                p.lists?.let { put("blocklists", listsJson(ctx, it)) }
            }
        })
    }

    /** link:<kind> = direct, but only over that kind of network (blocked on the other). */
    fun routes(): List<String> = listOf("direct", "block") + tunnels.map { "tunnel:${it.name}" } + listOf("link:wifi", "link:mobile")

    /** As stored in settings.json: the tunnels' secrets sealed by [v] (throws when it cannot seal). */
    fun toStoreJson(v: Vault): JSONObject = toJson().put("tunnels", JSONArray(tunnels.map { it.toStoreJson(v) }))
        .put("hidden_warnings", HiddenWarning.listJson(hiddenWarnings)) // file only: toJson (the core's) leaves it out
        .put("mullvad", MullvadLogin.storeJson(mullvadLogins, v)) // file only, sealed
        .put("mullvad_exits", JSONArray(mullvadExits.map { it.toJson() }))

    /**
     * Fail closed for locked tunnels (keys not readable on this device): they are left
     * out, with every tunnel that goes through one (multi-hop), and every route that
     * names one of them blocks instead. With Tor for everything on a locked Tor tunnel,
     * everything blocks. Settings without locked tunnels come back unchanged.
     */
    fun withoutLocked(): Settings {
        if (tunnels.none { it.locked }) return this
        val gone = tunnels.filter { it.locked }.map { it.name }.toMutableSet()
        while (true) {
            val more = tunnels.filter { it.name !in gone && it.via in gone }.map { it.name }
            if (more.isEmpty()) break
            gone += more
        }
        val left = tunnels.filter { it.name !in gone }
        if (torAll && tunnels.firstOrNull { it.isTor }?.name in gone) {
            return copy(tunnels = left, defaultRoute = "block", apps = apps.mapValues { "block" }, networks = emptyList(), torAll = false)
        }
        fun r(route: String) = if (route.startsWith("tunnel:") && route.removePrefix("tunnel:") in gone) "block" else route
        return copy(
            tunnels = left,
            defaultRoute = r(defaultRoute),
            apps = apps.mapValues { (_, route) -> r(route) },
            networks = networks.map { it.copy(route = r(it.route)) },
        )
    }

    /** As the core gets it: the keys in clear (only in memory, handed to the Go core). */
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
        // one Wi-Fi's profile before the one for all Wi-Fi networks (the core takes the first that fits)
        put("networks", JSONArray(networks.sortedBy { it.wifi.isEmpty() }.map { it.toJson() }))
        put("tor_all", torAll)
        put("level", level.key)
        // older versions read "pro" (Normal/Pro): going back keeps the choice
        put("pro", level != Level.Simple)
        put("strict_check", strictCheck)
        put("opsec_undo", JSONObject(opsecUndo))
        put("defense", defense)
        put("net_classes", JSONObject(netClasses))
        if (allowText.isNotEmpty()) put("allow_text", allowText) // the file's; the core gets the list file instead, see coreJson
    }

    /** The core's config: app rules by UID instead of package name. */
    fun coreJson(ctx: Context): String {
        if (tunnels.any { it.locked }) return withoutLocked().coreJson(ctx)
        val pm = ctx.packageManager
        fun uid(pkg: String): Int? = try {
            pm.getApplicationInfo(pkg, 0).uid
        } catch (e: PackageManager.NameNotFoundException) {
            null // uninstalled
        }
        val uids = JSONObject()
        for ((pkg, route) in apps) uid(pkg)?.let { uids.put(it.toString(), route) }
        val lists = listsJson(ctx, filterLists)
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
                .put("owner_unknown", Levels.ownerUnknown(level))
                .apply { engineExes(ctx); allowJson(ctx) }
                .toString()
        }
        return toJson()
            .put("networks", coreNetworks(ctx))
            .put("apps", uids)
            .put("blocklists", lists)
            .put("unfiltered", JSONArray(unfiltered.mapNotNull { uid(it)?.toString() }))
            .put("stats_path", java.io.File(ctx.filesDir, "stats.json").path)
            // as on the desktop: public DoH endpoints and Firefox's canary get NXDOMAIN,
            // so browsers stay on our DNS (route + filter)
            .put("block_doh", true)
            // a connection whose owner Android cannot name: default route, dropped in Opsec
            .put("owner_unknown", Levels.ownerUnknown(level))
            .apply { engineExes(ctx); allowJson(ctx) }
            .toString()
    }

    /** The user's allowlist as a list file for the core (names it never blocks, for every app). */
    private fun JSONObject.allowJson(ctx: Context) {
        remove("allow_text")
        if (Blocklists.writeAllow(ctx, allowText)) put("allow_lists", JSONArray().put(JSONObject().put("name", "allow").put("path", Blocklists.allowFile(ctx).path)))
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
        put("defense_dir", Defense.dir(ctx).path) // cache of the defense lists and first-contact memory (local only)
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
        /** settings.json still holds a tunnel's keys in clear (written before the vault). */
        fun hasClearSecrets(o: JSONObject): Boolean {
            val ts = o.optJSONArray("tunnels") ?: return false
            return (0 until ts.length()).any { ts.optJSONObject(it)?.has("conf") == true }
        }

        /** [v] opens the sealed secrets; null (or a key that does not fit) leaves those tunnels locked. */
        fun fromJson(o: JSONObject, v: Vault? = null): Settings {
            val ts = o.optJSONArray("tunnels") ?: JSONArray()
            val apps = o.optJSONObject("apps") ?: JSONObject()
            fun strings(key: String): List<String>? = o.optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } }
            return Settings(
                tunnels = (0 until ts.length()).map { Tunnel.fromStoreJson(ts.getJSONObject(it), v) },
                defaultRoute = o.optString("default", "block"),
                apps = apps.keys().asSequence().associateWith { apps.getString(it) },
                directDns = o.optString("direct_dns", "1.1.1.1"),
                filterLists = strings("filter_lists")?.filter { Blocklists.known(it) } ?: Blocklists.DEFAULT,
                unfiltered = strings("unfiltered_apps")?.toSet() ?: emptySet(),
                onDemand = o.optBoolean("on_demand", true),
                dnsServers = strings("dns_servers")?.filter { isDnsAddress(it) } ?: DEFAULT_DNS,
                ignoreTunnelDns = o.optBoolean("ignore_tunnel_dns", false),
                torAll = o.optBoolean("tor_all", false),
                level = Level.from(o.optString("level").ifEmpty { null }, if (o.has("pro")) o.optBoolean("pro") else null),
                strictCheck = o.optBoolean("strict_check", false),
                defense = o.optBoolean("defense", false),
                netClasses = o.optJSONObject("net_classes")?.let { u -> u.keys().asSequence().associateWith { Defense.migrate(u.optString(it)) }.filterValues { it in Defense.CLASSES } } ?: emptyMap(),
                opsecUndo = o.optJSONObject("opsec_undo")?.let { u -> u.keys().asSequence().associateWith { u.optBoolean(it) } } ?: emptyMap(),
                hiddenWarnings = HiddenWarning.listFrom(o.optJSONArray("hidden_warnings")),
                allowText = o.optString("allow_text"),
                mullvadLogins = MullvadLogin.listFrom(o.optJSONArray("mullvad"), v),
                mullvadExits = MullvadExit.listFrom(o.optJSONArray("mullvad_exits")),
                networks = o.optJSONArray("networks")?.let { a ->
                    (0 until a.length()).map { a.getJSONObject(it) }.filter { it.optString("link") in NetProfile.LINKS }
                        .map { NetProfile.fromJson(it) }
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

    /** Before the first unlock after boot (Direct Boot) the app's files are not readable. */
    private fun unlocked(ctx: Context) = ctx.getSystemService(UserManager::class.java)?.isUserUnlocked != false

    /** The move of clear keys into the vault failed once in this process: not again on every load. */
    @Volatile private var migrationFailed = false

    /**
     * The settings; tunnels whose keys cannot be opened come back locked (see
     * [Settings.withoutLocked]). Not readable (locked phone, damaged file): the
     * defaults, which block everything. A file from before the vault (keys in
     * clear) is sealed and rewritten here, once.
     */
    @Synchronized
    fun load(ctx: Context, v: Vault = Vault.keystore): Settings {
        if (!unlocked(ctx)) return Settings()
        val o = try {
            JSONObject(String(file(ctx).readFully()))
        } catch (e: Exception) {
            return Settings()
        }
        val s = try {
            Settings.fromJson(o, v)
        } catch (e: Exception) {
            return Settings()
        }
        if (Settings.hasClearSecrets(o) && !migrationFailed) migrate(ctx, s, v)
        return s
    }

    /**
     * Rewrites a settings.json with keys in clear as sealed. The new file replaces the
     * old one atomically (AtomicFile); afterwards the old file's bytes, still reachable
     * through the handle opened before, are overwritten with zeros. Any failure (key
     * store not available): the old file stays as it was, the app runs on with it.
     * Flash storage may keep old blocks elsewhere (wear levelling); the overwrite is
     * what an app can do, the key store protects every file written from now on.
     */
    private fun migrate(ctx: Context, s: Settings, v: Vault) {
        val base = File(ctx.filesDir, FILE)
        val old = runCatching { if (base.exists()) RandomAccessFile(base, "rw") else null }.getOrNull()
        try {
            save(ctx, s, v)
        } catch (e: Exception) {
            migrationFailed = true
            android.util.Log.w("Shunt", "vault: tunnel keys stay in the old file for now: ${e.javaClass.simpleName}")
            runCatching { old?.close() }
            return
        }
        old?.use { runCatching { wipe(it) } }
        android.util.Log.i("Shunt", "vault: tunnel keys moved into the key store")
    }

    /** Overwrites a file's bytes with zeros and syncs them to the disk. */
    fun wipe(f: RandomAccessFile) {
        val zeros = ByteArray(4096)
        var left = f.length()
        f.seek(0)
        while (left > 0) {
            val n = minOf(left, zeros.size.toLong()).toInt()
            f.write(zeros, 0, n)
            left -= n
        }
        f.fd.sync()
    }

    /**
     * Writes the settings with the tunnels' secrets sealed. Sealed before the file is
     * touched: when the key store cannot seal, this throws and the old file stays.
     */
    @Synchronized
    fun save(ctx: Context, s: Settings, v: Vault = Vault.keystore) {
        check(unlocked(ctx)) { "phone not unlocked yet" }
        val bytes = s.toStoreJson(v).toString(2).toByteArray()
        val f = file(ctx)
        val out = f.startWrite()
        try {
            out.write(bytes)
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
            mullvadExits = s.mullvadExits.map { if (it.tunnel == from) it.copy(tunnel = to) else it },
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
