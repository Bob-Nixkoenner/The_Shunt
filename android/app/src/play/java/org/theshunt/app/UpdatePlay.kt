package org.theshunt.app

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Play build: only says that a newer version exists; Google Play does the update. */
private fun openPlay(ctx: Context) {
    val id = ctx.packageName
    try {
        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$id")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (e: ActivityNotFoundException) {
        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$id")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
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
            ShuntButton("Get the update in Google Play", { openPlay(ctx) }, kind = Tone.Ok)
            Hint("Google Play installs the update. It can take a little while until Play offers a new version.")
        }
        note?.let { Hint(it) }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Include pre-releases (rc)", fontSize = 14.sp, modifier = Modifier.weight(1f))
            Switch(pre, { pre = it; Updater.setPrereleases(ctx, it) })
        }
        Hint("Only asks GitHub which version is the newest when you press Check. Nothing runs in the background.")
    }
}
