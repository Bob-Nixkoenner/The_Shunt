package org.theshunt.app

import android.content.Context
import android.content.pm.PackageManager
import org.json.JSONArray
import org.json.JSONObject

/** One imported WireGuard tunnel (the wg-quick file as text). */
data class Tunnel(val name: String, val conf: String)

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
        put("tunnels", JSONArray(tunnels.map { JSONObject().put("name", it.name).put("conf", it.conf) }))
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
            .put("unfiltered", JSONArray(unfiltered.mapNotNull { uid(it) }))
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
                    Tunnel(t.getString("name"), t.getString("conf"))
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

    fun load(ctx: Context): Settings = try {
        Settings.fromJson(JSONObject(ctx.openFileInput(FILE).bufferedReader().readText()))
    } catch (e: Exception) {
        Settings()
    }

    fun save(ctx: Context, s: Settings) {
        ctx.openFileOutput(FILE, Context.MODE_PRIVATE).use { it.write(s.toJson().toString(2).toByteArray()) }
    }

    /** Turns a file name or QR import into a tunnel name like on the desktop: a-z 0-9 -, max. 10. */
    fun tunnelName(raw: String, taken: Collection<String>): String {
        var base = raw.substringBeforeLast(".conf").lowercase().replace('_', '-')
            .filter { it in 'a'..'z' || it in '0'..'9' || it == '-' }.trimStart('-').take(10)
        if (base.isEmpty()) base = "vpn"
        var name = base
        var i = 2
        while (name in taken) name = base.take(8) + i++
        return name
    }
}
