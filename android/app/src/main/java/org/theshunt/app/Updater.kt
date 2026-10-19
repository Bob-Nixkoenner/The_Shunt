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

    private fun open(url: String): HttpURLConnection = (URL(url).openConnection() as HttpURLConnection).apply {
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

    private fun download(url: String, to: File, limit: Long) {
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

    /** Downloads and verifies the release APK. Blocking; throws if anything is off. */
    fun fetch(ctx: Context, r: Release): File {
        val dir = File(ctx.cacheDir, "update").apply { deleteRecursively(); mkdirs() }
        val sums = File(dir, "SHA256SUMS").also { download(r.sumsUrl, it, 1 shl 20) }
        val sig = File(dir, "SHA256SUMS.sig").also { download(r.sigUrl, it, 1 shl 16) }
        val name = "shunt-${r.tag}-android.apk"
        val want = Mobile.verifyUpdate(sums.readText(), sig.readText(), name)
        if (want.isEmpty()) error("the signed list has no $name")
        val apk = File(dir, name).also { download(r.apkUrl, it, 200L shl 20) }
        val md = MessageDigest.getInstance("SHA-256")
        apk.inputStream().use { i ->
            val buf = ByteArray(64 * 1024)
            while (true) { val n = i.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        val got = md.digest().joinToString("") { "%02x".format(it) }
        if (got != want) {
            apk.delete()
            error("checksum does not match the signed list - not installed")
        }
        return apk
    }

    fun canInstall(ctx: Context) = ctx.packageManager.canRequestPackageInstalls()

    fun askInstallPermission(ctx: Context) {
        ctx.startActivity(Intent(AndroidSettings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    /** Hands the verified APK to the system installer (it asks the user to confirm). */
    fun install(ctx: Context, apk: File, done: (String) -> Unit) {
        val action = "${ctx.packageName}.UPDATE_RESULT"
        val inst = ctx.packageManager.packageInstaller
        val rx = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                when (i.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        @Suppress("DEPRECATION")
                        val confirm = if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                        else i.getParcelableExtra(Intent.EXTRA_INTENT)
                        confirm?.let { c.startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                    }
                    PackageInstaller.STATUS_SUCCESS -> { c.unregisterReceiver(this); done("Updated.") }
                    else -> {
                        c.unregisterReceiver(this)
                        done("Install failed: " + (i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "unknown error"))
                    }
                }
            }
        }
        ctx.registerReceiver(rx, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        val id = inst.createSession(params)
        inst.openSession(id).use { s ->
            apk.inputStream().use { i -> s.openWrite("shunt.apk", 0, apk.length()).use { o -> i.copyTo(o); s.fsync(o) } }
            val pi = PendingIntent.getBroadcast(ctx, id, Intent(action).setPackage(ctx.packageName), PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            s.commit(pi.intentSender)
        }
    }
}

@Composable
fun UpdateSection(say: (String) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var found by remember { mutableStateOf<Updater.Release?>(null) }
    var note by remember { mutableStateOf<String?>(null) }
    var pre by remember { mutableStateOf(Updater.prereleases(ctx)) }

    Section("Update", action = {
        ShuntButton(if (busy) "Working…" else "Check", {
            busy = true
            note = null
            scope.launch {
                runCatching { withContext(Dispatchers.IO) { Updater.check(ctx) } }
                    .onSuccess { found = it; note = if (it == null) "You have the newest version." else null }
                    .onFailure { found = null; note = "Check failed: ${it.message}" }
                busy = false
            }
        }, enabled = !busy)
    }) {
        KV("Installed", Updater.current(ctx), mono = true)
        found?.let { r ->
            KV("Available", r.tag, mono = true)
            ShuntButton(if (busy) "Working…" else "Download and install", {
                if (!Updater.canInstall(ctx)) {
                    say("Allow \"Install unknown apps\" for The Shunt, then press the button again.")
                    Updater.askInstallPermission(ctx)
                } else {
                    busy = true
                    scope.launch {
                        runCatching { withContext(Dispatchers.IO) { Updater.fetch(ctx, r) } }
                            .onSuccess { apk -> runCatching { Updater.install(ctx, apk, say) }.onFailure { say("Install failed: ${it.message}") } }
                            .onFailure { say("Update stopped: ${it.message}") }
                        busy = false
                    }
                }
            }, kind = Tone.Ok, enabled = !busy)
            Hint("The app is checked against the release's signed checksum list first. The VPN stops while Android installs the update.")
        }
        note?.let { Hint(it) }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Include pre-releases (rc)", fontSize = 14.sp, modifier = Modifier.weight(1f))
            Switch(pre, { pre = it; Updater.setPrereleases(ctx, it) })
        }
        Hint("Only asks GitHub when you press Check. Nothing runs in the background.")
    }
}
