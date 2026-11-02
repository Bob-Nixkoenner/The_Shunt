package org.theshunt.app

import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext

/**
 * F-Droid build: no update check, no network call. F-Droid does the updates. The section says
 * which build this is and what it leaves out compared with the GitHub and Google Play builds.
 */
@Composable
fun UpdateSection(say: (String) -> Unit) {
    val ctx = LocalContext.current
    Section("Update") {
        KV("Installed", Updater.current(ctx), mono = true)
        KV("Build", "F-Droid", mono = true)
        Hint("This is the F-Droid version. F-Droid installs the updates; the app never checks for them itself.")
        Hint("The GitHub and Google Play versions are fuller: they bring their own Tor (no Orbot needed). This version uses Orbot for Tor tunnels.")
    }
}
