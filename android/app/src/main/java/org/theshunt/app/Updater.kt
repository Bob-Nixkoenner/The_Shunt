package org.theshunt.app

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings as AndroidSettings
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.theshunt.mobile.Mobile
import org.json.JSONArray
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Update from GitHub releases, only when the user asks (no background checks,
 * nothing is sent but the request itself). The APK is installed only if the
 * release's SHA256SUMS carries the release key's signature (checked by the Go
 * core) and the APK matches its listed hash.
 */
object Updater {
    private const val REPO = "Bob-Nixkoenner/The_Shunt"
    private const val PREFS = "update"
    private val VER = Regex("""^v?(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z]+)\.?(\d+)?)?$""")

    class Release(val tag: String, val apkUrl: String, val sumsUrl: String, val sigUrl: String, val size: Long)

    fun current(ctx: Context): String = ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "?"

    fun prereleases(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("pre", current(ctx).contains("-"))
    fun setPrereleases(ctx: Context, on: Boolean) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("pre", on).apply()

    /** > 0 if a is newer than b; null if either is not a release tag (e.g. a "-dirty" test build). */
    fun compare(a: String, b: String): Int? {
        val ma = VER.matchEntire(a) ?: return null
        val mb = VER.matchEntire(b) ?: return null
        for (i in 1..3) {
            val c = ma.groupValues[i].toInt().compareTo(mb.groupValues[i].toInt())
            if (c != 0) return c
        }
        val pa = ma.groupValues[4]
        val pb = mb.groupValues[4]
        if (pa.isEmpty() && pb.isEmpty()) return 0
        if (pa.isEmpty()) return 1
        if (pb.isEmpty()) return -1
        val c = pa.compareTo(pb)
        if (c != 0) return c
        return (ma.groupValues[5].toIntOrNull() ?: 0).compareTo(mb.groupValues[5].toIntOrNull() ?: 0)
    }

    internal fun open(url: String): HttpURLConnection = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = 15000
        readTimeout = 30000
        setRequestProperty("Accept", "application/vnd.github+json")
        instanceFollowRedirects = true
    }

    /** Newest release this device can update to, null if it is up to date. Blocking. */
    fun check(ctx: Context): Release? {
        val body = open("https://api.github.com/repos/$REPO/releases?per_page=30").run {
            if (responseCode != 200) error("GitHub: HTTP $responseCode")
            inputStream.use { it.readBytes().decodeToString() }
        }
        val rs = JSONArray(body)
        val cur = current(ctx)
        val pre = prereleases(ctx)
        for (i in 0 until rs.length()) { // newest first
            val r = rs.getJSONObject(i)
            if (r.optBoolean("draft") || (r.optBoolean("prerelease") && !pre)) continue
            val tag = r.getString("tag_name")
            val newer = compare(tag, cur) ?: return null // test build: never asks
            if (newer <= 0) return null
            val assets = r.getJSONArray("assets")
            val urls = HashMap<String, Pair<String, Long>>()
            for (j in 0 until assets.length()) {
                val a = assets.getJSONObject(j)
                urls[a.getString("name")] = a.getString("browser_download_url") to a.optLong("size")
            }
            val apk = urls["shunt-$tag-android.apk"] ?: continue
            val sums = urls["SHA256SUMS"] ?: continue
            val sig = urls["SHA256SUMS.sig"] ?: continue
            return Release(tag, apk.first, sums.first, sig.first, apk.second)
        }
        return null
    }

    internal fun download(url: String, to: File, limit: Long) {
        open(url).run {
            if (responseCode != 200) error("download: HTTP $responseCode")
            inputStream.use { i -> to.outputStream().use { o ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = i.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > limit) error("download is larger than expected")
                    o.write(buf, 0, n)
                }
            } }
        }
    }
}
