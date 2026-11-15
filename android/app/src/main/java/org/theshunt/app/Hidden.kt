package org.theshunt.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * A warning the user hid on the Status tab: [until] in ms since 1970, 0 =
 * for good. [msg] and [args] keep the text, so the list can show it while
 * the warning is not there. Kept only in this phone's settings file (never
 * handed to the core, never sent).
 */
data class HiddenWarning(val key: String, val until: Long, val msg: String, val args: List<Pair<String, String>> = emptyList()) {
    fun active(now: Long) = until == 0L || now < until

    fun toJson(): JSONObject = JSONObject().put("key", key).put("until", until).put("msg", msg)
        .put("args", JSONObject().apply { for ((k, v) in args) put(k, v) })

    companion object {
        fun fromJson(o: JSONObject): HiddenWarning? {
            val key = o.optString("key")
            if (HiddenWarnings.idOf(key) !in HiddenWarnings.HIDEABLE) return null
            val a = o.optJSONObject("args")
            return HiddenWarning(key, o.optLong("until", 0L), o.optString("msg"),
                a?.keys()?.asSequence()?.map { it to a.optString(it) }?.toList() ?: emptyList())
        }

        fun listJson(l: List<HiddenWarning>) = JSONArray(l.map { it.toJson() })

        fun listFrom(a: JSONArray?): List<HiddenWarning> =
            if (a == null) emptyList() else (0 until a.length()).mapNotNull { a.optJSONObject(it)?.let(::fromJson) }
    }
}

/**
 * Hiding warnings, the same rules as the desktop (internal/check/ignore.go):
 * only notes about one's own settings, never a "bad" one, never a state of
 * the moment or a leak (no kill switch, Private DNS, VPN error). A Go test
 * keeps [HIDEABLE] equal to the desktop's list.
 */
object HiddenWarnings {
    /** Finding ID → what it is about ("" = the finding as a whole), as in ignore.go. */
    val HIDEABLE = mapOf(
        "rule.direct" to "rule",
        "rule.plaindns" to "rule",
        "default.direct" to "",
        "network.direct" to "link",
        "default.block" to "",
        "network.ssid_only" to "name",
        "gateway.direct" to "name",
        "gateway.noroute" to "name",
        "stealth.unset" to "",
        "stealth.home" to "",
        "stealth.winname" to "",
        "quiet.off" to "",
        "inbound.off" to "",
        "captive.on" to "",
        "filter.redundant" to "",
        "ovpn.cbc" to "tunnel",
        "ovpn.auth" to "tunnel",
        "ovpn.compress" to "tunnel",
        "ovpn.nowrap" to "tunnel",
        "ovpn.tls" to "tunnel",
        "ovpn.nocerttype" to "tunnel",
    )

    const val DAY = 24 * 60 * 60 * 1000L
    const val WEEK = 7 * DAY

    fun idOf(key: String) = key.substringBefore(':')

    /** The key [f] is hidden under, null when it may not be hidden. */
    fun key(f: Finding): String? {
        if (f.bad) return null
        val subj = HIDEABLE[f.id] ?: return null
        return if (subj.isEmpty()) f.id else f.id + ":" + f.subject
    }

    /** The entries in effect at [now] (expired ones drop out). */
    fun active(s: Settings, now: Long): List<HiddenWarning> = s.hiddenWarnings.filter { it.active(now) }.sortedBy { it.key }

    /** [s] with [f] hidden for [forMs] (0 = for good); unchanged when [f] may not be hidden. */
    fun hide(s: Settings, f: Finding, forMs: Long, now: Long): Settings {
        val k = key(f) ?: return s
        val it = HiddenWarning(k, if (forMs > 0) now + forMs else 0L, f.msg, f.args)
        return s.copy(hiddenWarnings = s.hiddenWarnings.filter { h -> h.key != k && h.active(now) } + it)
    }

    /** [s] with [key] shown again (and expired entries dropped). */
    fun show(s: Settings, key: String, now: Long): Settings =
        s.copy(hiddenWarnings = s.hiddenWarnings.filter { it.key != key && it.active(now) })

    /** Whether [f] is hidden at [now]. */
    fun hidden(s: Settings, f: Finding, now: Long): Boolean {
        val k = key(f) ?: return false
        return s.hiddenWarnings.any { it.key == k && it.active(now) }
    }
}
