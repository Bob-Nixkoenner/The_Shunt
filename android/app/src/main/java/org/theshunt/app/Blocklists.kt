package org.theshunt.app

import android.content.Context
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * DNS filter lists, the same ones the desktop uses (HaGeZi and RPiList, thank
 * you for maintaining them; both are downloaded when switched on, not part of the app).
 * Downloaded by the app itself – it is excluded from its own VPN, so this
 * goes out directly – and refreshed once a day when the VPN starts.
 */
object Blocklists {
    const val SOURCE = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/"

    /** HaGeZi's lists (https://github.com/hagezi/dns-blocklists, GPL-3.0), adblock format: "||name^" covers subdomains. */
    const val HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/"

    /**
     * One list: its name (file name on RPiList, or "hagezi-…" for HaGeZi, then
     * [url] is the file), what it blocks, size in MB (0 = unknown).
     */
    class Entry(val name: String, val what: String, val mb: Double = 0.0, val url: String? = null)

    private fun hagezi(name: String, file: String, what: String, mb: Double) = Entry(name, what, mb, "$HAGEZI$file.txt")

    /**
     * The lists of the desktop's DNS filter tab, grouped the same way (see
     * internal/ui/static/filter.js), without what a phone does not have:
     * Windows and Office telemetry, smart-TV lists.
     */
    val GROUPS: List<Pair<String, List<Entry>>> = listOf(
        // Light, Pro and Pro++ build on each other (a "mini" is the same list, smaller): one of them is enough
        "HaGeZi – all-round" to listOf(
            hagezi("hagezi-light", "light", "Multi LIGHT: basic protection, hardly ever breaks anything", 1.6),
            hagezi("hagezi-pro-mini", "pro.mini", "Multi PRO mini: extended protection, made for phones (recommended)", 1.8),
            hagezi("hagezi-pro", "pro", "Multi PRO: extended protection", 4.5),
            hagezi("hagezi-pro-plus-mini", "pro.plus.mini", "Multi PRO++ mini: more aggressive", 2.1),
        ),
        "HaGeZi – threats, scams and pop-ups" to listOf(
            hagezi("hagezi-tif-mini", "tif.mini", "Threat intelligence (mini): malware, phishing, C2", 4.4),
            hagezi("hagezi-fake", "fake", "Scams, fake shops and fake sites", 0.4),
            hagezi("hagezi-popupads", "popupads", "Pop-up ads", 1.0),
        ),
        "HaGeZi – trackers built into devices" to listOf(
            hagezi("hagezi-native-samsung", "native.samsung", "Samsung", 0.0),
            hagezi("hagezi-native-xiaomi", "native.xiaomi", "Xiaomi", 0.0),
            hagezi("hagezi-native-huawei", "native.huawei", "Huawei", 0.0),
            hagezi("hagezi-native-oppo", "native.oppo-realme", "OPPO and Realme", 0.0),
            hagezi("hagezi-native-vivo", "native.vivo", "Vivo", 0.0),
            hagezi("hagezi-native-amazon", "native.amazon", "Amazon", 0.0),
            hagezi("hagezi-native-tiktok", "native.tiktok", "TikTok fingerprinting", 0.0),
        ),
        "Ads" to listOf(Entry("easylist", "Ads and tracking – the starter list", 3.8), Entry("spam.mails", "Spam senders", 4.4)),
        "Malware" to listOf(Entry("malware", "Malware", 14.9)),
        "Phishing and scam" to listOf(
            Entry("Phishing-Angriffe", "Phishing", 4.2), Entry("crypto", "Crypto scams and mining", 2.7),
            Entry("Fake-Science", "Fake science"), Entry("Corona-Blocklist", "Corona fakes", 7.5),
        ),
        "Fake shops and subscription traps" to listOf(Entry("notserious", "Dubious shops and sites", 2.2), Entry("Streaming", "Streaming sites", 0.5)),
        "Domain squatting" to listOf(
            Entry("DomainSquatting1", "Domain squatting 1", 32.9), Entry("DomainSquatting2", "Domain squatting 2", 18.8),
        ),
        "Tracking and telemetry" to listOf(Entry("samsung", "Samsung telemetry")),
        "Youth protection" to listOf(
            Entry("child-protection", "Child protection", 5.9), Entry("gambling", "Gambling", 40.0),
            Entry("DatingSites", "Dating sites", 7.3), Entry("proxies", "Proxy and anonymiser services", 3.6),
        ) + (1..6).map { Entry("pornblock$it", "Adult content $it", if (it == 6) 7.2 else 33.0) },
        "Other" to listOf(Entry("SupportingRussia", "Companies supporting Russia"), Entry("Overblock", "Aggressive, breaks sites")),
    )

    /** Name to short description, all groups. */
    val ALL: Map<String, String> = GROUPS.flatMap { it.second }.associate { it.name to it.what }

    /** On by default. */
    val DEFAULT = listOf("hagezi-pro-mini", "Phishing-Angriffe")

    /** From this size on a list is large for a phone (download and memory): asked before switching it on. */
    const val BIG_MB = 15.0

    /** Web page of a list (shown when its name is tapped). */
    fun page(name: String) =
        if (name.startsWith("hagezi-")) "https://github.com/hagezi/dns-blocklists" else "https://github.com/RPiList/specials/blob/master/Blocklisten/$name"

    private val urls: Map<String, String> = GROUPS.flatMap { it.second }.mapNotNull { e -> e.url?.let { e.name to it } }.toMap()

    /** Where a list is downloaded from. */
    fun url(name: String) = urls[name] ?: (SOURCE + name)

    // --- the user's own lists (Pro): a name "my-…" and an https address, kept in blocklists/custom.json
    const val CUSTOM_PREFIX = "my-"
    const val MAX_CUSTOM = 10
    private const val MAX_BYTES = 120L * 1024 * 1024

    /** Whether a list name is one of the built-in lists or one the user added. */
    fun known(name: String) = name in ALL || name.startsWith(CUSTOM_PREFIX)

    data class Custom(val name: String, val url: String)

    private fun customFile(ctx: Context) = File(File(ctx.filesDir, "blocklists"), "custom.json")

    @Synchronized
    fun customLists(ctx: Context): List<Custom> = try {
        val a = org.json.JSONArray(customFile(ctx).readText())
        (0 until a.length()).map { a.getJSONObject(it) }.map { Custom(it.getString("name"), it.getString("url")) }
            .filter { it.name.startsWith(CUSTOM_PREFIX) }
    } catch (e: Exception) {
        emptyList()
    }

    @Synchronized
    private fun saveCustom(ctx: Context, list: List<Custom>) {
        customFile(ctx).parentFile?.mkdirs()
        customFile(ctx).writeText(org.json.JSONArray(list.map { org.json.JSONObject().put("name", it.name).put("url", it.url) }).toString())
    }

    /** "my-" + the label as a-z 0-9 -, at most 10 characters after the prefix; made unique. */
    fun customName(label: String, taken: Collection<String>): String {
        val base = label.lowercase().replace('_', '-').filter { it in 'a'..'z' || it in '0'..'9' || it == '-' }.trim('-').take(10).ifEmpty { "list" }
        var n = CUSTOM_PREFIX + base
        var i = 2
        while (n in taken) n = CUSTOM_PREFIX + base.take(8) + i++
        return n
    }

    /**
     * Adds a list by address and downloads it now. Throws with a reason when the address is not
     * https, the download fails or the file is not a list (an error page, a wrong format): then
     * nothing is kept. Not on the main thread.
     */
    fun addCustom(ctx: Context, label: String, address: String): String {
        val url = address.trim()
        require(url.startsWith("https://") && url.length > 12 && url.none { it.isWhitespace() }) { T("The address must start with https://") }
        val list = customLists(ctx)
        require(list.size < MAX_CUSTOM) { T("At most {n} own lists", "n" to MAX_CUSTOM) }
        require(list.none { it.url == url }) { T("This list is added already") }
        val name = customName(label, list.map { it.name } + ALL.keys)
        saveCustom(ctx, list + Custom(name, url))
        try {
            download(ctx, name, url)
        } catch (e: Exception) {
            removeCustom(ctx, name)
            throw e
        }
        return name
    }

    fun removeCustom(ctx: Context, name: String) {
        saveCustom(ctx, customLists(ctx).filter { it.name != name })
        file(ctx, name).delete()
        counted.remove(name)
    }

    /** Downloads one list and checks that it is usable; the old copy stays when anything fails. */
    private fun download(ctx: Context, name: String, url: String): Boolean {
        val f = file(ctx, name)
        f.parentFile?.mkdirs()
        val tmp = File(f.path + ".part")
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 10_000
            c.readTimeout = 30_000
            c.instanceFollowRedirects = true
            if (c.responseCode != 200) throw IllegalStateException("HTTP ${c.responseCode}")
            var n = 0L
            c.inputStream.use { input -> tmp.outputStream().use { out ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val r = input.read(buf)
                    if (r < 0) break
                    n += r
                    if (n > MAX_BYTES) throw IllegalStateException(T("The list is bigger than {mb} MB", "mb" to (MAX_BYTES / 1024 / 1024)))
                    out.write(buf, 0, r)
                }
            } }
            try {
                org.theshunt.mobile.Mobile.checkFilterFile(tmp.path, false)
            } catch (e: Exception) {
                throw IllegalStateException(T("This is not a list the filter can read: {error}", "error" to (e.message ?: "?")))
            }
            return tmp.renameTo(f)
        } finally {
            c.disconnect()
            tmp.delete()
        }
    }

    // --- names that are never blocked: the user's text becomes one list file for the core
    fun allowFile(ctx: Context) = File(File(ctx.filesDir, "blocklists"), "allow-user")

    /** Writes the allowlist file when the text changed; false when there is nothing to allow. */
    fun writeAllow(ctx: Context, text: String): Boolean {
        val f = allowFile(ctx)
        if (text.isBlank()) { f.delete(); return false }
        f.parentFile?.mkdirs()
        if (!f.exists() || f.readText() != text) f.writeText(text)
        return true
    }

    /** Names in a downloaded list (0 if not downloaded): lines that are not comments. */
    fun count(ctx: Context, name: String): Int {
        val f = file(ctx, name)
        if (!f.exists()) return 0
        // reading a big list takes a while: count again only when the file changed
        val stamp = f.length() to f.lastModified()
        counted[name]?.let { (s, n) -> if (s == stamp) return n }
        val n = f.useLines { ls -> ls.count { l -> l.isNotBlank() && !l.trimStart().startsWith("#") && !l.trimStart().startsWith("!") } }
        counted[name] = stamp to n
        return n
    }

    private val counted = java.util.concurrent.ConcurrentHashMap<String, Pair<Pair<Long, Long>, Int>>()

    private const val MAX_AGE_MS = 24 * 3600 * 1000L

    fun file(ctx: Context, name: String) = File(File(ctx.filesDir, "blocklists"), name)

    /**
     * Downloads missing and day-old lists; an old copy is kept if the
     * download fails. Returns whether any list changed.
     */
    fun refresh(ctx: Context, names: Collection<String>): Boolean {
        var changed = false
        for (name in names) {
            val f = file(ctx, name)
            if (f.exists() && System.currentTimeMillis() - f.lastModified() < MAX_AGE_MS) continue
            try {
                if (name.startsWith(CUSTOM_PREFIX)) {
                    val u = customLists(ctx).firstOrNull { it.name == name }?.url ?: continue
                    if (download(ctx, name, u)) changed = true
                    continue
                }
                f.parentFile?.mkdirs()
                val tmp = File(f.path + ".part")
                val c = URL(url(name)).openConnection() as HttpURLConnection
                c.connectTimeout = 10_000
                c.readTimeout = 30_000
                c.inputStream.use { input -> tmp.outputStream().use { input.copyTo(it) } }
                if (c.responseCode != 200) throw IllegalStateException("HTTP ${c.responseCode}")
                if (tmp.renameTo(f)) changed = true
            } catch (e: Exception) {
                Log.w("Shunt", "blocklist $name: ${e.message}")
            }
        }
        return changed
    }
}
