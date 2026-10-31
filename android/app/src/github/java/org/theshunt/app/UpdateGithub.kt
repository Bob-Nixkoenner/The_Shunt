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

// Download, verification and installation of the update (github flavor only: Play updates apps itself).

/** Downloads and verifies the release APK. Blocking; throws if anything is off. */
fun Updater.fetch(ctx: Context, r: Updater.Release): File {
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

fun Updater.canInstall(ctx: Context) = ctx.packageManager.canRequestPackageInstalls()

fun Updater.askInstallPermission(ctx: Context) {
    ctx.startActivity(Intent(AndroidSettings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

/** Hands the verified APK to the system installer (it asks the user to confirm). */
fun Updater.install(ctx: Context, apk: File, done: (String) -> Unit) {
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
                PackageInstaller.STATUS_SUCCESS -> { c.unregisterReceiver(this); done(T("Updated.")) }
                else -> {
                    c.unregisterReceiver(this)
                    done(T("Install failed: {error}", "error" to (i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: T("unknown error"))))
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

@Composable
fun UpdateSection(say: (String) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var found by remember { mutableStateOf<Updater.Release?>(null) }
    var note by remember { mutableStateOf<String?>(null) }
    var pre by remember { mutableStateOf(Updater.prereleases(ctx)) }

    Section("Update", action = {
        ShuntButton(if (busy) T("Working…") else T("Check"), {
            busy = true
            note = null
            scope.launch {
                runCatching { withContext(Dispatchers.IO) { Updater.check(ctx) } }
                    .onSuccess { found = it; note = if (it == null) T("You have the newest version.") else null }
                    .onFailure { found = null; note = T("Check failed: {error}", "error" to it.message) }
                busy = false
            }
        }, enabled = !busy)
    }) {
        KV("Installed", Updater.current(ctx), mono = true)
        found?.let { r ->
            KV("Available", r.tag, mono = true)
            ShuntButton(if (busy) T("Working…") else T("Download and install"), {
                if (!Updater.canInstall(ctx)) {
                    say(T("Allow \"Install unknown apps\" for The Shunt, then press the button again."))
                    Updater.askInstallPermission(ctx)
                } else {
                    busy = true
                    scope.launch {
                        runCatching { withContext(Dispatchers.IO) { Updater.fetch(ctx, r) } }
                            .onSuccess { apk -> runCatching { Updater.install(ctx, apk, say) }.onFailure { say(T("Install failed: {error}", "error" to it.message)) } }
                            .onFailure { say(T("Update stopped: {error}", "error" to it.message)) }
                        busy = false
                    }
                }
            }, kind = Tone.Ok, enabled = !busy)
            Hint("The app is checked against the release's signed checksum list first. The VPN stops while Android installs the update.")
        }
        note?.let { Hint(it) }
        SwitchRow("Include pre-releases (rc)", pre, { pre = it; Updater.setPrereleases(ctx, it) }, bold = false)
        Hint("Only asks GitHub when you press Check. Nothing runs in the background.")
    }
}
