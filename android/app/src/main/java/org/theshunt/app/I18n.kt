package org.theshunt.app

import android.content.Context
import android.content.res.AssetManager
import org.json.JSONObject
import java.util.Locale

/**
 * The app's texts in the user's language. The catalog is the one of the
 * desktop apps (internal/i18n/lang/<code>.json, packed as assets): the
 * English text is the key, {placeholders} are filled by T(), and a text
 * without translation shows in English. The language is the one Android
 * gives this app (system language, or the per-app language on Android 13+),
 * looked up on every call, so a change applies as soon as the screen is made again.
 */
object I18n {
    private val cache = HashMap<String, Map<String, String>>()
    private var assets: AssetManager? = null

    fun init(ctx: Context) { assets = ctx.applicationContext.assets }

    private fun dict(): Map<String, String> {
        val lang = Locale.getDefault().language
        if (lang == "en") return emptyMap()
        synchronized(cache) { return cache.getOrPut(lang) { load(lang) } }
    }

    private fun load(lang: String): Map<String, String> = try {
        val text = assets!!.open("$lang.json").bufferedReader().use { it.readText() }
        val o = JSONObject(text).getJSONObject("strings")
        HashMap<String, String>().also { m -> for (k in o.keys()) m[k] = o.getString(k) }
    } catch (e: Exception) {
        emptyMap() // no file for this language: English
    }

    fun t(s: String): String = dict()[s] ?: s

    fun t(s: String, vararg kv: Pair<String, Any?>): String {
        var r = t(s)
        for ((k, v) in kv) r = r.replace("{$k}", v.toString())
        return r
    }

    fun tn(n: Int, one: String, many: String, vararg kv: Pair<String, Any?>): String =
        t(if (n == 1) one else many, "n" to n, *kv)
}

fun T(s: String): String = I18n.t(s)
fun T(s: String, vararg kv: Pair<String, Any?>): String = I18n.t(s, *kv)
fun Tn(n: Int, one: String, many: String, vararg kv: Pair<String, Any?>): String = I18n.tn(n, one, many, *kv)
