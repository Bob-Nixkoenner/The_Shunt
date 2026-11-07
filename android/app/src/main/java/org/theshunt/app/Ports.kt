package org.theshunt.app

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Apps that wait for connections from other devices (KDE Connect, Syncthing,
 * Termux SSH …) and the ports they use: portlist/portlist.json in the repo,
 * packed as an asset, and refreshable from GitHub (anyone can propose an app
 * with a pull request).
 */
object Portlist {
    const val URL = "https://raw.githubusercontent.com/Bob-Nixkoenner/The_Shunt/main/portlist/portlist.json"

    class App(val name: String, val ports: List<String>, val note: String)

    private fun file(ctx: Context) = File(ctx.filesDir, "portlist.json")

    fun parse(text: String): List<App> {
        val a = JSONObject(text).getJSONArray("apps")
        return (0 until a.length()).map { i ->
            val o = a.getJSONObject(i)
            val p = o.getJSONArray("ports")
            App(o.getString("name"), (0 until p.length()).map { p.getString(it) }, o.optString("note"))
        }.filter { it.ports.all(::validPort) }
    }

    /** tcp/PORT, udp/PORT or tcp/FIRST-LAST (at most 64 ports), like the core wants it. */
    fun validPort(s: String): Boolean {
        val m = Regex("""^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$""").matchEntire(s.trim().lowercase()) ?: return false
        val a = m.groupValues[2].toInt()
        val b = m.groupValues[3].ifEmpty { m.groupValues[2] }.toInt()
        return a in 1..65535 && b in a..65535 && b - a < 64
    }

    /** The downloaded list if there is a good one, else the one in the app. */
    fun load(ctx: Context): List<App> {
        runCatching { file(ctx).takeIf { it.exists() }?.let { return parse(it.readText()).ifEmpty { null } ?: throw Exception() } }
        return runCatching { parse(ctx.assets.open("portlist.json").bufferedReader().use { it.readText() }) }.getOrDefault(emptyList())
    }

    /** Downloads the list; true if it was good and is kept. The app is excluded from its own VPN, so this goes out directly. */
    fun refresh(ctx: Context): Boolean = try {
        val c = URL(URL).openConnection() as HttpURLConnection
        c.connectTimeout = 8000; c.readTimeout = 8000
        val text = c.inputStream.bufferedReader().use { it.readText() }
        if (text.length > 200_000 || parse(text).isEmpty()) false else { file(ctx).writeText(text); true }
    } catch (e: Exception) { false }
}

/** Ports tab: per tunnel, which apps on this phone may be reached from the tunnel. Everything else stays closed. */
@Composable
fun PortsScreen(settings: Settings, update: (Settings) -> Unit, say: (String) -> Unit) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    val scope = rememberCoroutineScope()
    var apps by remember { mutableStateOf(Portlist.load(ctx)) }
    val tunnels = settings.tunnels.filter { !it.isTor }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Gap.screen), verticalArrangement = Arrangement.spacedBy(Gap.sections)) {
        Section("Ports") {
            Text(T("Other devices in a tunnel can only reach this phone on the ports you open here. Everything else stays closed. Restart the VPN after a change."), color = c.muted, fontSize = 13.sp)
            ShuntButton(T("Update the app list"), {
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { Portlist.refresh(ctx) }
                    if (ok) apps = Portlist.load(ctx)
                    say(if (ok) T("App list updated.") else T("Could not update the app list."))
                }
            })
        }
        if (tunnels.isEmpty()) Section("Tunnels") { Text(T("No tunnels yet."), color = c.muted) }
        for (t in tunnels) Section("Tunnel") {
            RouteTag("tunnel:${t.name}")
            fun set(ports: List<String>) {
                update(settings.copy(tunnels = settings.tunnels.map { if (it.name == t.name) it.copy(inbound = ports.distinct()) else it }))
                say(T("Restart the VPN to apply this."))
            }
            for (a in apps) {
                val on = t.inbound.containsAll(a.ports)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f).padding(end = Gap.beside)) {
                        Text(a.name, color = c.text, fontSize = 14.sp)
                        Text(a.ports.joinToString(" ") + if (a.note.isEmpty()) "" else "\n" + a.note, color = c.muted, fontSize = 12.sp)
                    }
                    Switch(
                        checked = on,
                        onCheckedChange = { want -> set(if (want) t.inbound + a.ports else t.inbound - a.ports.toSet()) },
                        colors = SwitchDefaults.colors(checkedTrackColor = c.accent, checkedThumbColor = c.accentInk),
                    )
                }
            }
            // own ports: everything open that is not one of the listed apps
            val known = apps.flatMap { it.ports }.toSet()
            val own = t.inbound.filter { it !in known }
            for (p in own) Row(verticalAlignment = Alignment.CenterVertically) {
                Text(p, Modifier.weight(1f), color = c.text, fontSize = 14.sp)
                ShuntButton(T("Remove"), { set(t.inbound - p) })
            }
            var text by remember { mutableStateOf("") }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                OutlinedTextField(text, { text = it }, Modifier.weight(1f), label = { Text(T("Own port, e.g. tcp/8080")) }, singleLine = true)
                ShuntButton(T("Open"), {
                    if (Portlist.validPort(text)) { set(t.inbound + text.trim().lowercase()); text = "" }
                    else say(T("Use tcp/PORT, udp/PORT or tcp/FIRST-LAST."))
                })
            }
        }
    }
}
