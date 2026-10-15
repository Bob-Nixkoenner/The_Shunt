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
    /** OpenVPN only: name of the WireGuard tunnel that carries it (multi-hop), "" = direct. */
    val via: String = "",
) {
    val isOpenVPN get() = type == OPENVPN

    fun toJson(): JSONObject = JSONObject().put("name", name).put("conf", conf).apply {
        if (isOpenVPN) put("type", OPENVPN).put("user", user).put("pass", pass).put("via", via)
    }

    companion object {
        const val WIREGUARD = "wireguard"
        const val OPENVPN = "openvpn"
    }
}

/**
 * The app's configuration: tunnels, default route and one route per app
 * (by package name). Kept as JSON in the app's private files.
 * Routes are named as in shunt.toml: "direct", "block", "tunnel:<name>".
 */
data class Settings(
    val tunnels: List<Tunnel> = emptyList(),
    val defaultRoute: String = "block",
    val apps: Map<String, String> = emptyMap(),
    val directDns: String = "1.1.1.1",
    /** DNS filter lists (Blocklists.ALL names); empty = filter off. */
    val filterLists: List<String> = Blocklists.DEFAULT,
    /** Apps (package names) whose DNS is not filtered. */
    val unfiltered: Set<String> = emptySet(),
) {
    fun routes(): List<String> = listOf("direct", "block") + tunnels.map { "tunnel:${it.name}" }

    fun toJson(): JSONObject = JSONObject().apply {
        put("tunnels", JSONArray(tunnels.map { it.toJson() }))
        put("default", defaultRoute)
        put("apps", JSONObject(apps))
        put("direct_dns", directDns)
        put("filter_lists", JSONArray(filterLists))
        put("unfiltered_apps", JSONArray(unfiltered.toList()))
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
        return toJson()
            .put("apps", uids)
            .put("blocklists", lists)
            .put("unfiltered", JSONArray(unfiltered.mapNotNull { uid(it)?.toString() }))
            .put("stats_path", java.io.File(ctx.filesDir, "stats.json").path)
            .apply {
                // openvpn ships as lib/<abi>/libopenvpn.so (Android runs programs only from there)
                val exe = File(ctx.applicationInfo.nativeLibraryDir, "libopenvpn.so")
                if (exe.exists()) put("openvpn", exe.path).put("work_dir", ctx.filesDir.path)
            }
            .toString()
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
                filterLists = strings("filter_lists") ?: Blocklists.DEFAULT,
                unfiltered = strings("unfiltered_apps")?.toSet() ?: emptySet(),
            )
        }
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
