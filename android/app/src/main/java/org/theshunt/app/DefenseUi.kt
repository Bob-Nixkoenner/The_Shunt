package org.theshunt.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Status tab, Max Security only (Levels "defense.ui"), while the defense is on:
 * a thermometer (heat 0-100 with its level) and the last events. Everything
 * comes from the core on this phone; nothing is sent anywhere.
 */
@Composable
fun DefenseStatusSection(settings: Settings, status: JSONObject?) {
    if (!settings.shows("defense.ui") || !settings.defense) return
    val c = LocalShunt.current
    val running by VpnState.running.collectAsStateWithLifecycle()
    val d = status?.optJSONObject("defense")
    val heat = (d?.optInt("heat") ?: 0).coerceIn(0, 100)
    val level = d?.optString("level").orEmpty().ifEmpty { "quiet" }
    val color = when (level) { "attack" -> c.bad; "hot" -> c.warn; "noticed" -> c.info; else -> c.ok }
    var events by remember { mutableStateOf<List<Defense.Event>>(emptyList()) }
    // the list changes rarely: look every 3 s while this tab is shown and the VPN runs
    LaunchedEffect(running) {
        while (running) {
            val e = VpnState.engine
            if (e != null) events = withContext(Dispatchers.IO) { runCatching { Defense.parseEvents(e.defenseEvents(0)) }.getOrDefault(emptyList()) }.takeLast(8).reversed()
            delay(3000)
        }
    }
    Section("Defense") {
        if (!running) {
            Hint("Turn the VPN on: the defense watches what the VPN sees.")
            return@Section
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.beside)) {
            Text(T(Defense.levelLabel(level)), color = color, fontWeight = FontWeight.Bold, modifier = Modifier.width(76.dp))
            Box(Modifier.weight(1f).height(10.dp).clip(RoundedCornerShape(5.dp)).background(c.panel2)) {
                Box(Modifier.fillMaxWidth(heat / 100f).fillMaxHeight().background(color))
            }
            Text("$heat", color = c.muted, fontSize = 13.sp, modifier = Modifier.width(30.dp))
        }
        Hint(T("Network class: {class}", "class" to T(Defense.classLabel(d?.optString("class").orEmpty().ifEmpty { "public" }))))
        if (events.isEmpty()) Hint("No events yet. The first minutes of an app are learning only.")
        for (ev in events) Text(Defense.text(ev), color = if (ev.severity >= 3) c.bad else c.text, fontSize = 13.sp, lineHeight = 18.sp)
    }
}

/** Settings tab, Max Security only: the switch (off by default), the network classes and what is not possible here. */
@Composable
fun DefenseSettingsSection(settings: Settings, update: (Settings) -> Unit) {
    if (!settings.shows("defense.ui")) return
    val c = LocalShunt.current
    Section("Defense") {
        SwitchRow(
            "Watch for attacks", settings.defense, { update(settings.copy(defense = it)) },
            "Reports DNS tunnelling, apps that connect at regular intervals, apps that contact something new and addresses on known bad lists. It only reports: it blocks nothing and sends nothing anywhere.",
        )
        Text(T("Network class"), color = c.text, fontWeight = FontWeight.SemiBold)
        Hint("Public: strictest watching (default, also for unknown networks). Trusted: quiet warnings. Managed: for a workplace network.")
        for ((link, label) in listOf("wifi" to "Wi-Fi", "mobile" to "Mobile data")) {
            // big system font: the name on its own line, the buttons one under the other (no word breaks in the middle)
            val classButtons: @Composable (Modifier) -> Unit = { m ->
                for (k in Defense.CLASSES) ShuntButton(
                    Defense.classLabel(k),
                    { update(settings.copy(netClasses = settings.netClasses + (link to k))) },
                    kind = if (Defense.classFor(settings, link) == k) Tone.Ok else Tone.Neutral,
                    modifier = m,
                )
            }
            if (bigFont()) {
                Text(T(label), color = c.text)
                ButtonRow(classButtons)
            } else Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                Text(T(label), color = c.text, modifier = Modifier.width(88.dp))
                classButtons(Modifier.weight(1f))
            }
        }
        Hint("Not available on Android: checks of the router (ARP, DHCP, IPv6), decoy ports, scan detection and the check for a fake Wi-Fi with the same name.")
    }
}
