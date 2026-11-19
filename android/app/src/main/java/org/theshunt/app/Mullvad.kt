package org.theshunt.app

import org.json.JSONArray
import org.json.JSONObject
import org.theshunt.mobile.Mobile
import java.net.HttpURLConnection
import java.net.URL

/**
 * Mullvad: log in with an account number, pick a server (country, city or one), make an
 * ordinary WireGuard tunnel from it, or a chain of tunnels one behind the other.
 *
 * The network calls are made here (Android's DNS; the app is outside its own VPN, so they
 * go out directly); the logic (keys, server choice, the WireGuard file, chains) is the Go
 * core's (mobile/mullvad.go), the same as on the desktop. The account number and the key
 * are secrets: they live sealed in settings.json (see [MullvadLogin.storeJson]), never in
 * the core's config, never in a log.
 */
data class MullvadLogin(
    val name: String,
    val account: String,
    val deviceId: String,
    val deviceName: String,
    val privateKey: String,
    val ipv4: String,
    val ipv6: String,
) {
    /** "••••3456": what the screen shows of the number. */
    val masked get() = if (account.length >= 4) "••••" + account.takeLast(4) else ""

    fun secretJson(): String = JSONObject().put("account", account).put("device_id", deviceId)
        .put("private_key", privateKey).put("ipv4", ipv4).put("ipv6", ipv6).toString()

    /** What the Go core needs to build a file. */
    fun coreJson(): String = JSONObject().put("private_key", privateKey).put("ipv4", ipv4).put("ipv6", ipv6).toString()

    companion object {
        /** Name and device name in clear, the rest sealed. */
        fun storeJson(list: List<MullvadLogin>, v: Vault): JSONArray = JSONArray(list.map {
            JSONObject().put("name", it.name).put("device", it.deviceName).put("secret", v.seal(it.secretJson()))
        })

        /** A login whose secret cannot be opened here (other phone) is dropped: log in again. */
        fun listFrom(a: JSONArray?, v: Vault?): List<MullvadLogin> {
            if (a == null || v == null) return emptyList()
            return (0 until a.length()).mapNotNull { i ->
                val o = a.optJSONObject(i) ?: return@mapNotNull null
                val s = v.open(o.optString("secret"))?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return@mapNotNull null
                MullvadLogin(o.optString("name"), s.optString("account"), s.optString("device_id"), o.optString("device"),
                    s.optString("private_key"), s.optString("ipv4"), s.optString("ipv6"))
            }
        }
    }
}

/** The server a Mullvad tunnel is on; [chain] names the chain it is a hop of ("" = single tunnel). */
data class MullvadExit(
    val tunnel: String,
    val account: String,
    val hostname: String,
    val country: String,
    val city: String,
    val provider: String = "",
    val chain: String = "",
) {
    fun toJson(): JSONObject = JSONObject().put("tunnel", tunnel).put("account", account).put("hostname", hostname)
        .put("country", country).put("city", city).put("provider", provider).put("chain", chain)

    companion object {
        fun fromJson(o: JSONObject) = MullvadExit(o.optString("tunnel"), o.optString("account"), o.optString("hostname"),
            o.optString("country"), o.optString("city"), o.optString("provider"), o.optString("chain"))

        fun listFrom(a: JSONArray?): List<MullvadExit> =
            if (a == null) emptyList() else (0 until a.length()).mapNotNull { a.optJSONObject(it)?.let(::fromJson) }
    }
}

/** An answer of Mullvad that is an error. */
class MullvadException(val code: String, text: String) : Exception(text)

/** What the user picks: a country ("de"), a city ("de-fra") or one server; all empty = any. */
data class MullvadChoice(val country: String = "", val city: String = "", val hostname: String = "") {
    fun json(): String = JSONObject().put("country", country).put("city", city).put("hostname", hostname).toString()
}

object MullvadApi {
    private const val BASE = "https://api.mullvad.net"

    private fun call(method: String, path: String, token: String? = null, body: JSONObject? = null): String {
        val c = URL(BASE + path).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.setRequestProperty("Accept", "application/json")
            if (token != null) c.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toString().toByteArray()) }
            }
            val ok = c.responseCode / 100 == 2
            val text = (if (ok) c.inputStream else c.errorStream)?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (!ok) {
                val o = runCatching { JSONObject(text) }.getOrNull()
                val code = o?.optString("code").orEmpty()
                throw MullvadException(code, when (code) {
                    "INVALID_ACCOUNT" -> T("Mullvad: this account number is not valid")
                    "MAX_DEVICES_REACHED" -> T("Mullvad: this account already has 5 devices; remove one at mullvad.net/account first")
                    else -> "Mullvad: " + (o?.optString("error")?.takeIf { it.isNotEmpty() } ?: "HTTP ${c.responseCode}")
                })
            }
            return text
        } finally {
            c.disconnect()
        }
    }

    fun token(account: String): String =
        JSONObject(call("POST", "/auth/v1/token", body = JSONObject().put("account_number", account))).getString("access_token")

    fun addDevice(token: String, pubkey: String): JSONObject =
        JSONObject(call("POST", "/accounts/v1/devices", token, JSONObject().put("pubkey", pubkey).put("hijack_dns", false)))

    fun deleteDevice(token: String, id: String) {
        require(Regex("^[0-9a-zA-Z-]{1,64}$").matches(id)) { "bad device id" }
        call("DELETE", "/accounts/v1/devices/$id", token)
    }

    @Volatile private var relays: String? = null
    @Volatile private var relaysAt = 0L

    /** The public relay list (no login needed), kept for ten minutes. */
    fun relays(): String {
        val cached = relays
        if (cached != null && System.currentTimeMillis() - relaysAt < 10 * 60_000) return cached
        return try {
            call("GET", "/public/relays/wireguard/v2").also { relays = it; relaysAt = System.currentTimeMillis() }
        } catch (e: Exception) {
            cached ?: throw e
        }
    }
}

/** What the screen needs of one country: its cities, each with its server host names. */
data class MullvadCity(val code: String, val name: String, val hosts: List<String>)
data class MullvadCountry(val code: String, val name: String, val cities: List<MullvadCity>)

/**
 * The Mullvad operations on [Settings]: each one returns the new settings (the caller saves
 * them) or throws; they call the network, so never on the main thread.
 */
object Mullvad {
    /** Same rule as tunnel names: a-z 0-9 -, 1 to 10 characters. */
    val NAME = Regex("^[a-z0-9][a-z0-9-]{0,9}$")
    const val DEFAULT_LOGIN = "main"

    fun countries(): List<MullvadCountry> {
        val a = JSONArray(Mobile.mullvadCountries(MullvadApi.relays()))
        return (0 until a.length()).map { i ->
            val c = a.getJSONObject(i)
            val cs = c.getJSONArray("cities")
            MullvadCountry(c.getString("code"), c.getString("name"), (0 until cs.length()).map { j ->
                val ci = cs.getJSONObject(j)
                val hs = ci.optJSONArray("hosts")
                MullvadCity(ci.getString("code"), ci.getString("name"), if (hs == null) emptyList() else (0 until hs.length()).map { hs.getString(it) })
            })
        }
    }

    /** Registers a new key as a device of the account. */
    fun login(s: Settings, rawName: String, rawAccount: String): Settings {
        val name = rawName.trim().ifEmpty { DEFAULT_LOGIN }
        require(NAME.matches(name)) { T("Account name: 1-10 characters a-z 0-9 -, starting with a letter or digit") }
        val account = Mobile.mullvadNormalizeAccount(rawAccount)
        require(s.mullvadLogins.none { it.name == name }) { T("An account \"{name}\" is logged in already; log it out first or choose another name", "name" to name) }
        require(s.mullvadLogins.none { it.account == account }) { T("This account is logged in already") }
        val token = MullvadApi.token(account)
        val key = JSONObject(Mobile.mullvadNewKey())
        val dev = MullvadApi.addDevice(token, key.getString("public"))
        val login = MullvadLogin(name, account, dev.getString("id"), dev.optString("name"), key.getString("private"),
            dev.getString("ipv4_address"), dev.optString("ipv6_address"))
        return s.copy(mullvadLogins = s.mullvadLogins + login)
    }

    /** How many tunnels the packets of a tunnel travel through before they leave. */
    fun depth(s: Settings, via: String): Int {
        var d = 0
        var v = via
        while (v.isNotEmpty() && d < 16) {
            val t = s.tunnels.firstOrNull { it.name == v } ?: break
            d++
            v = t.via
        }
        return d
    }

    private fun pickLogin(s: Settings, wanted: String): MullvadLogin {
        s.mullvadLogins.firstOrNull { it.name == wanted }?.let { return it }
        if (wanted.isEmpty() && s.mullvadLogins.size == 1) return s.mullvadLogins[0]
        throw IllegalArgumentException(
            if (wanted.isEmpty()) T("Several Mullvad accounts are logged in: say which one the tunnel uses") else T("No Mullvad account \"{name}\"", "name" to wanted))
    }

    private fun build(s: Settings, login: MullvadLogin, choice: MullvadChoice, via: String): Pair<String, JSONObject> {
        val r = JSONObject(Mobile.mullvadConf(MullvadApi.relays(), login.coreJson(), choice.json(), depth(s, via).toLong()))
        return r.getString("conf") to r
    }

    /** A new Mullvad tunnel, or the exit of a Mullvad tunnel that exists (its routes stay). */
    fun connect(s: Settings, tunnelName: String, loginName: String, choice: MullvadChoice, via: String): Settings {
        require(s.mullvadLogins.isNotEmpty()) { T("Log in to Mullvad first") }
        val mine = s.mullvadExits.firstOrNull { it.tunnel == tunnelName && s.tunnels.any { t -> t.name == tunnelName } }
        if (mine == null) {
            require(s.tunnels.none { it.name == tunnelName }) { T("A tunnel \"{name}\" exists already", "name" to tunnelName) }
            require(NAME.matches(tunnelName)) { T("Tunnel name: 1–10 characters a-z 0-9 -") }
        }
        val login = pickLogin(s, if (mine != null) mine.account else loginName)
        if (mine != null && loginName.isNotEmpty() && loginName != mine.account) {
            throw IllegalArgumentException(T("tunnel:{name} uses account \"{account}\"; to change that, delete the tunnel and add it again", "name" to tunnelName, "account" to mine.account))
        }
        val carrier = if (mine != null) s.tunnels.first { it.name == tunnelName }.via else via.removePrefix("tunnel:")
        require(carrier.isEmpty() || s.tunnels.any { it.name == carrier && !it.isOpenVPN && !it.isTor }) { T("The tunnel it should run through must be a WireGuard tunnel") }
        val (conf, info) = build(s, login, choice, carrier)
        Mobile.checkWireGuard(conf)
        val exit = MullvadExit(tunnelName, login.name, info.getString("hostname"), info.getString("country"), info.getString("city"), info.optString("provider"), mine?.chain.orEmpty())
        val first = s.tunnels.isEmpty() && s.defaultRoute == "block"
        return if (mine != null) {
            s.copy(
                tunnels = s.tunnels.map { if (it.name == tunnelName) it.copy(conf = conf) else it },
                mullvadExits = s.mullvadExits.map { if (it.tunnel == tunnelName) exit else it },
            )
        } else {
            s.copy(
                tunnels = s.tunnels + Tunnel(tunnelName, conf, via = carrier),
                defaultRoute = if (first) "tunnel:$tunnelName" else s.defaultRoute,
                mullvadExits = s.mullvadExits + exit,
            )
        }
    }

    /**
     * A chain of [hops] (2 to 4) Mullvad tunnels "NAME1" … "NAMEn", each running through the
     * one before, in other countries and (where possible) at other hosting providers. [logins]
     * (names; empty = all) are used in turn. Nothing is changed when one hop cannot be made.
     */
    fun chain(s: Settings, name: String, hops: Int, entry: String, exit: String, logins: List<String>, via: String): Settings {
        require(s.mullvadLogins.isNotEmpty()) { T("Log in to Mullvad first") }
        require(Regex("^[a-z0-9][a-z0-9-]{0,7}$").matches(name)) { T("Chain name: 1–8 characters a-z 0-9 -") }
        val names = (1..hops).map { "$name$it" }
        require(names.none { n -> s.tunnels.any { it.name == n } }) { T("A tunnel {name}1 exists already: choose another chain name", "name" to name) }
        val use = (if (logins.isEmpty()) s.mullvadLogins.map { it.name }.sorted() else logins).map { pickLogin(s, it) }
        val plan = JSONArray(Mobile.mullvadChainPick(MullvadApi.relays(), hops.toLong(), entry, exit))
        var cur = s
        var carrier = via.removePrefix("tunnel:")
        for (i in 0 until plan.length()) {
            val p = plan.getJSONObject(i)
            val login = use[i % use.size]
            val (conf, _) = build(cur, login, MullvadChoice(hostname = p.getString("hostname")), carrier)
            Mobile.checkWireGuard(conf)
            val first = cur.tunnels.isEmpty() && cur.defaultRoute == "block"
            cur = cur.copy(
                tunnels = cur.tunnels + Tunnel(names[i], conf, via = carrier),
                defaultRoute = if (first) "tunnel:${names[i]}" else cur.defaultRoute,
                mullvadExits = cur.mullvadExits + MullvadExit(names[i], login.name, p.getString("hostname"), p.getString("country"),
                    p.getString("city"), p.optString("provider"), name),
            )
            carrier = names[i]
        }
        return cur
    }

    /** Takes tunnels away, with everything that pointed at them (routes block, as when a tunnel is deleted). */
    fun withoutTunnels(s: Settings, gone: Set<String>): Settings {
        fun r(route: String) = if (route.startsWith("tunnel:") && route.removePrefix("tunnel:") in gone) "block" else route
        return s.copy(
            tunnels = s.tunnels.filter { it.name !in gone },
            defaultRoute = r(s.defaultRoute),
            apps = s.apps.mapValues { (_, route) -> r(route) },
            networks = s.networks.map { it.copy(route = r(it.route)) },
            mullvadExits = s.mullvadExits.filter { it.tunnel !in gone },
        )
    }

    /** Which tunnels still run through these ones (and are not among them). */
    private fun users(s: Settings, names: Set<String>): List<String> = s.tunnels.filter { it.via in names && it.name !in names }.map { it.name }

    fun deleteChain(s: Settings, chain: String): Settings {
        val hops = s.mullvadExits.filter { it.chain == chain }.map { it.tunnel }.toSet()
        require(hops.isNotEmpty()) { T("No chain \"{name}\"", "name" to chain) }
        val blocked = users(s, hops)
        require(blocked.isEmpty()) { T("Tunnels still run through this chain: {list}", "list" to blocked.joinToString(", ")) }
        return withoutTunnels(s, hops)
    }

    /** Removes a login: its tunnels (chains whole), then its device at Mullvad. */
    fun logout(s: Settings, name: String): Settings {
        val login = s.mullvadLogins.firstOrNull { it.name == name } ?: return s
        val mine = s.mullvadExits.filter { it.account == name }
        // a chain goes whole: a hop of another login that runs through one of these would be cut off
        val gone = mine.map { it.tunnel }.toMutableSet()
        val blocked = users(s, gone)
        require(blocked.isEmpty()) { T("Tunnels still run through these: {list}. Delete them first.", "list" to blocked.joinToString(", ")) }
        // the device first: when Mullvad cannot be reached the login stays and the user sees why
        try {
            MullvadApi.deleteDevice(MullvadApi.token(login.account), login.deviceId)
        } catch (e: MullvadException) {
            if (e.code != "INVALID_ACCOUNT") throw e // an account that is gone has no device to free
        }
        val out = withoutTunnels(s, gone)
        return out.copy(mullvadLogins = out.mullvadLogins.filter { it.name != name })
    }
}
