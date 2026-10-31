package org.theshunt.app

/**
 * Levels: what the app shows. Simple for people who just want the VPN to
 * work, Pro shows everything, Opsec shows everything too, with a violet
 * accent, an "OPSEC" band in the header, the emergency switch on the status
 * tab and a set of strict settings the user confirmed once (Opsec). The level
 * only hides things: hidden settings keep working.
 *
 * The same levels as the desktop window (internal/ui/static/levels.js).
 */
enum class Level(val key: String, val label: String) {
    Simple("simple", "Simple"), Pro("pro", "Pro"), Opsec("opsec", "Opsec");

    companion object {
        fun of(key: String?): Level? = entries.firstOrNull { it.key == key }

        /**
         * The stored level, or the one the old Normal/Pro switch ("pro" in
         * settings.json) becomes: Normal → Simple, Pro → Pro. A fresh install
         * (neither stored) starts in Simple.
         */
        fun from(stored: String?, oldPro: Boolean?): Level = of(stored) ?: if (oldPro == true) Pro else Simple
    }
}

/**
 * LEVEL_TABLE is the one place that says which part of the app shows in which
 * level (keys as on the desktop where the part exists on Android). A key
 * missing from the table shows everywhere.
 */
object Levels {
    private val PRO = setOf(Level.Pro, Level.Opsec)
    private val OPSEC = setOf(Level.Opsec)

    val TABLE: Map<String, Set<Level>> = mapOf(
        // Tor: existing Tor tunnels stay as a plain card; adding one, bridges,
        // new identity and the emergency switch are Pro (the switch stays
        // visible while it is on, see EmergencySection)
        "tor.add" to PRO,
        "tor.bridges" to PRO,
        "tor.newnym" to PRO,
        "tor.emergency" to PRO,
        // switching between the built-in Tor and Orbot, "Start now"
        "tor.client" to PRO,
        // tunnels: a tunnel through another one (shown in Simple while one is set)
        "tunnel.multihop" to PRO,
        // apps: Simple keeps the route per app and "All other apps"; the
        // per-network defaults (network profiles) are Pro (shown while set)
        "apps.netprofiles" to PRO,
        // DNS servers asked after the tunnel's own
        "dns.servers" to PRO,
        // security check: Simple shows only what is really bad
        "checks.notes" to PRO,
        // opsec only: the band in the header, the emergency switch on the status tab
        "opsec.band" to OPSEC,
        "opsec.emergency" to OPSEC,
    )

    fun shows(key: String, level: Level): Boolean = TABLE[key]?.contains(level) ?: true
}

/**
 * One line of the Opsec list. [kind] says what the app can do about it on
 * Android: SET = a setting of this app (a switch, on by default, undone when
 * leaving Opsec), SYSTEM = a setting only the user can change in Android's
 * settings (shown with its state when the app can see it), BUILTIN = always
 * the case here, NA = not available on Android (with the reason).
 */
class OpsecItem(
    val id: String,
    val text: String,
    val help: String,
    val kind: Kind,
    /** Why it is built in / not available, or where to set it (SYSTEM). */
    val note: String = "",
    val isOn: (Settings) -> Boolean = { false },
    val set: (Settings, Boolean) -> Settings = { s, _ -> s },
) {
    enum class Kind { SET, SYSTEM, BUILTIN, NA }
}

object Opsec {
    val ITEMS = listOf(
        OpsecItem(
            "killswitch", "Kill switch: Always-on VPN and “Block connections without VPN”",
            "Android's own kill switch: no app gets out while the VPN starts, restarts or crashes.",
            OpsecItem.Kind.SYSTEM, "Only you can turn it on: Android settings → VPN → The Shunt.",
        ),
        OpsecItem(
            "privatedns", "Private DNS off",
            "Android's Private DNS sends the names every app looks up past the tunnels and the DNS filter.",
            OpsecItem.Kind.SYSTEM, "Only you can turn it off: Android settings → Network & internet → Private DNS.",
        ),
        OpsecItem(
            "doh", "Encrypted DNS of apps blocked",
            "Known DNS-over-HTTPS servers get no answer, so browsers use the DNS of their route.",
            OpsecItem.Kind.BUILTIN, "Always on (Android).",
        ),
        OpsecItem(
            "strict", "Stricter security check",
            "The app checks your settings more strictly: all other apps going direct and OpenVPN files without tls-crypt count as bad, apps that go direct as warnings. They show as banners on the Status tab.",
            OpsecItem.Kind.SET, isOn = { it.strictCheck }, set = { s, on -> s.copy(strictCheck = on) },
        ),
        OpsecItem(
            "stealth", "Random MAC address in Wi-Fi networks",
            "Networks you join do not see your phone's real hardware address.",
            OpsecItem.Kind.SYSTEM, "Set by Android (on by default since Android 10: Wi-Fi settings → the network → Privacy). The Shunt cannot change it.",
        ),
        OpsecItem(
            "captive", "No check for Wi-Fi login pages", "",
            OpsecItem.Kind.NA, "Not available on Android: The Shunt makes no such check here; Android checks each network itself and apps cannot turn that off.",
        ),
        OpsecItem(
            "inbound", "Incoming connections closed", "",
            OpsecItem.Kind.NA, "Not available on Android: The Shunt has no filter for incoming connections here.",
        ),
        OpsecItem(
            "clock", "Clock check through the tunnel", "",
            OpsecItem.Kind.NA, "Not available on Android: the phone sets its own clock.",
        ),
        OpsecItem(
            "tcpts", "TCP timestamps off", "",
            OpsecItem.Kind.NA, "Not available on Android: only the system can change this.",
        ),
        OpsecItem(
            "icmpts", "No answers to ICMP timestamp requests", "",
            OpsecItem.Kind.NA, "Not available on Android: only the system can change this.",
        ),
    )

    /**
     * Switching to Opsec: the ticked SET items that are not on yet get
     * switched on; their earlier value goes into the undo list (an earlier,
     * kept Opsec change keeps its value from before that time).
     */
    fun switchOn(s: Settings, ticked: Set<String>): Settings {
        var out = s
        val undo = s.opsecUndo.toMutableMap()
        for (it in ITEMS) {
            if (it.kind != OpsecItem.Kind.SET || it.id !in ticked || it.isOn(out)) continue
            undo.putIfAbsent(it.id, it.isOn(out))
            out = it.set(out, true)
        }
        return out.copy(level = Level.Opsec, opsecUndo = undo)
    }

    /** Leaving Opsec for [to]: the ticked items go back to their earlier value, the undo list is emptied. */
    fun switchOff(s: Settings, to: Level, undoIds: Set<String>): Settings {
        var out = s
        for (it in ITEMS) {
            val before = s.opsecUndo[it.id] ?: continue
            if (it.id in undoIds) out = it.set(out, before)
        }
        return out.copy(level = to, opsecUndo = emptyMap())
    }

    /** The items Opsec changed and can put back. */
    fun undoable(s: Settings): List<OpsecItem> = ITEMS.filter { it.id in s.opsecUndo }
}

/**
 * A finding of the strict check ([Settings.strictCheck]): [msg] is the
 * English text (translated by the UI) with {placeholders} from [args].
 * The same findings as the desktop's daemon.config_check = "strict", as far
 * as they exist on Android.
 */
data class Finding(val bad: Boolean, val id: String, val msg: String, val args: List<Pair<String, String>> = emptyList())

object StrictCheck {
    private fun direct(route: String) = route.startsWith("direct") || route.startsWith("link:")

    /**
     * [noWrap]: OpenVPN tunnels whose file has no tls-crypt or tls-auth;
     * [label]: the name of an app for its package.
     */
    fun findings(s: Settings, noWrap: Collection<String>, label: (String) -> String = { it }): List<Finding> {
        val out = mutableListOf<Finding>()
        if (s.tunnels.isNotEmpty() && direct(s.defaultRoute) && !s.torAll) {
            out += Finding(true, "default.direct", "The default route is direct: programs without a rule are not protected by a tunnel.")
        }
        for (p in s.networks) if (s.tunnels.isNotEmpty() && direct(p.route) && !s.torAll) {
            out += Finding(true, "network.direct", if (p.link == "wifi") "On Wi-Fi all other apps go direct: they are not protected by a tunnel." else "On mobile data all other apps go direct: they are not protected by a tunnel.")
        }
        for (t in s.tunnels) if (t.isOpenVPN && t.name in noWrap) {
            out += Finding(true, "ovpn.nowrap", "Tunnel “{tunnel}”: the OpenVPN file has no tls-crypt or tls-auth: the server answers anyone, port scans and attacks on the TLS handshake are not held back.", listOf("tunnel" to t.name))
        }
        // direct rules stay a warning (a printer or the home network needs them)
        if (!s.torAll) for ((pkg, route) in s.apps.entries.sortedBy { it.key }) if (direct(route)) {
            out += Finding(false, "rule.direct", "Rule “{rule}” sends traffic direct, past every tunnel.", listOf("rule" to label(pkg)))
        }
        return out
    }
}
