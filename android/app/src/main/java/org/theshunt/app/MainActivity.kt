@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package org.theshunt.app

import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.res.painterResource
import android.Manifest
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.format.Formatter
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.border
import androidx.compose.ui.Alignment
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.em
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.theshunt.mobile.Mobile

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        UiPrefs.load(this)
        setContent {
            ShuntTheme(UiPrefs.dark()) {
                Surface(Modifier.fillMaxSize(), color = LocalShunt.current.bg) { ConsentGate(onDecline = { finish() }) { App() } }
            }
        }
    }
}

/** Polls the core's status once a second while the VPN runs. */
@Composable
private fun rememberStatus(): State<JSONObject?> {
    val running by VpnState.running.collectAsStateWithLifecycle()
    val status = remember { mutableStateOf<JSONObject?>(null) }
    LaunchedEffect(running) {
        var shown = ""
        while (running) {
            val st = VpnState.engine?.status()?.let { JSONObject(it) }
            status.value = st
            VpnState.refreshKillSwitch() // turned on in the settings meanwhile?
            val ov = st?.optJSONObject("override")
            val now = "${ov?.optBoolean("panic")}/${(ov?.optLong("pass_left") ?: 0) > 0}/${VpnState.lockdown.value}"
            if (now != shown) { shown = now; VpnState.refreshNotification() }
            delay(1000)
        }
        status.value = null
    }
    return status
}

@Composable
private fun App() {
    val ctx = LocalContext.current
    var settings by remember { mutableStateOf(Store.load(ctx)) }
    var tab by remember { mutableIntStateOf(0) }
    var message by remember { mutableStateOf<String?>(null) }
    val status by rememberStatus()
    val update: (Settings) -> Unit = { s ->
        settings = s
        Store.save(ctx, s)
        ShuntVpnService.applyRules(ctx, s)?.let { message = it }
    }
    // Opsec: the violet accent over the whole app (status colours stay)
    ShuntTheme(UiPrefs.dark(), opsec = settings.level == Level.Opsec) {
        val c = LocalShunt.current

        Scaffold(
            containerColor = c.bg,
            topBar = { Header(status, settings.shows("opsec.band")) },
            bottomBar = {
                NavigationBar(containerColor = c.panel) {
                    val filterIcon = painterResource(R.drawable.ic_tab_filter)
                    listOf(
                        "Status" to rememberVectorPainter(Icons.Filled.Home), "Tunnels" to rememberVectorPainter(Icons.Filled.Lock),
                        "Apps" to rememberVectorPainter(Icons.AutoMirrored.Filled.List), "Filter" to filterIcon,
                        "View" to rememberVectorPainter(Icons.Filled.Settings),
                    ).forEachIndexed { i, (label, icon) ->
                        NavigationBarItem(
                            selected = tab == i, onClick = { tab = i }, icon = { Icon(icon, null) },
                            label = { Text(T(label), maxLines = 1, softWrap = false, fontWeight = if (tab == i) FontWeight.Bold else FontWeight.Normal) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedTextColor = c.text, unselectedTextColor = c.muted, indicatorColor = c.panel2,
                                selectedIconColor = c.accent, unselectedIconColor = c.muted,
                            ),
                        )
                    }
                }
            },
        ) { pad ->
            Box(Modifier.padding(pad).fillMaxSize()) {
                when (tab) {
                    0 -> StatusScreen(settings, status, update) { message = it }
                    1 -> TunnelsScreen(settings, update) { message = it }
                    2 -> AppsScreen(settings, update)
                    3 -> FilterScreen(settings, update, status)
                    4 -> SettingsScreen(settings, update)
                }
            }
        }
        message?.let {
            AlertDialog(onDismissRequest = { message = null }, confirmButton = { TextButton({ message = null }) { Text(T("OK")) } }, text = { Text(it) })
        }
    }
}

/** Sticky header like the web UI: logo, state pill, PANIC; in Opsec a slim "OPSEC" band above it. */
@Composable
private fun Header(status: JSONObject?, band: Boolean = false) {
    val c = LocalShunt.current
    val running by VpnState.running.collectAsStateWithLifecycle()
    val lockdown by VpnState.lockdown.collectAsStateWithLifecycle()
    val ov = status?.optJSONObject("override")
    val panic = ov?.optBoolean("panic") ?: false
    val passLeft = ov?.optLong("pass_left") ?: 0L
    Column(Modifier.background(c.bg).statusBarsPadding()) {
        if (band) Text(
            "OPSEC", Modifier.fillMaxWidth().background(c.accent).padding(vertical = 2.dp)
                .semantics { contentDescription = T("Opsec level") },
            color = c.accentInk, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 3.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            ShuntLogo()
            Spacer(Modifier.width(10.dp))
            Text(T("The Shunt"), fontWeight = FontWeight.Bold, fontSize = 17.sp, color = c.text)
            Spacer(Modifier.width(12.dp))
            when {
                !running -> Pill("off")
                panic -> Pill("PANIC", Tone.Bad)
                passLeft > 0 -> Pill(T("PASS {time}", "time" to "%d:%02d".format(passLeft / 60, passLeft % 60)), Tone.Bad)
                !lockdown -> Pill("no kill switch", Tone.Warn)
                else -> Pill("protected", Tone.Ok)
            }
            Spacer(Modifier.weight(1f))
            if (running) {
                ShuntButton(if (panic) T("Release") else T("PANIC"), {
                    VpnState.engine?.setPanic(!panic)
                }, kind = Tone.Bad)
            }
        }
        HorizontalDivider(color = if (band) c.accent else c.line)
    }
}

@Composable
private fun StatusScreen(settings: Settings, status: JSONObject?, update: (Settings) -> Unit, say: (String) -> Unit) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    val running by VpnState.running.collectAsStateWithLifecycle()
    val error by VpnState.error.collectAsStateWithLifecycle()
    val lockdown by VpnState.lockdown.collectAsStateWithLifecycle()
    val privateDns by VpnState.privateDns.collectAsStateWithLifecycle()
    var confirmReset by remember { mutableStateOf(false) }
    var confirmPass by remember { mutableStateOf(false) }
    var leak by remember { mutableStateOf<JSONArray?>(null) }
    var leakRunning by remember { mutableStateOf(false) }
    var range by remember { mutableStateOf("24h") }
    val history by rememberHistory(range)
    val askVpn = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) ShuntVpnService.start(ctx)
    }
    // the status notification needs this on Android 13+; the VPN runs without it too
    val askNotify = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    val start = {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) askNotify.launch(Manifest.permission.POST_NOTIFICATIONS)
        val intent = VpnService.prepare(ctx)
        if (intent != null) askVpn.launch(intent) else ShuntVpnService.start(ctx)
    }
    val ov = status?.optJSONObject("override")
    val panic = ov?.optBoolean("panic") ?: false
    val passLeft = ov?.optLong("pass_left") ?: 0L

    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(Gap.screen),
        verticalArrangement = Arrangement.spacedBy(Gap.sections),
    ) {
        error?.let { Banner("VPN error", it, bad = true) }
        if (panic) Banner("Panic", "Everything is blocked, running connections were cut.", bad = true)
        else if (passLeft > 0) Banner(
            "Pass – unprotected",
            "Everything goes direct: your real IP, no tunnels, no blocks, no DNS filter. Connections opened meanwhile are cut when it ends.",
            bad = true,
        ) { ShuntLink("End pass now", { VpnState.engine?.pass(0) }) }
        if (running && !lockdown) {
            // the only real kill switch on Android is the system's: without
            // it, apps get out unprotected while the VPN (re)starts or crashes
            Banner(
                "No kill switch",
                "While the VPN starts, restarts or crashes, apps can get out unprotected. Turn on \"Always-on VPN\" and \"Block connections without VPN\" for The Shunt.",
            ) { ShuntLink("Open VPN settings", { ctx.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }) }
        }
        if (running && settings.defaultRoute == "block" && !panic) {
            Banner(
                "All other apps are blocked",
                "The default route is \"block\": only apps with their own rule get out. Change \"All other apps\" under Apps.",
            )
        }
        if (running && privateDns) {
            Banner(
                "Private DNS is on",
                "Android sends DNS for all apps to its \"Private DNS\" server, past the tunnels and the DNS filter. Set Private DNS to \"Off\" so every app resolves through its route.",
            ) { ShuntLink("Open network settings", { ctx.startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)) }) }
        }
        if (settings.strictCheck) StrictBanners(settings)
        // Opsec: the emergency switch where you see it first
        if (settings.shows("opsec.emergency")) EmergencySection(settings, update, prominent = true)

        Section("VPN") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f).padding(end = Gap.beside)) {
                    Text(if (running) T("On") else T("Off"), fontWeight = FontWeight.Bold, color = c.text)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(T("default route ").trim(), Modifier.align(Alignment.CenterVertically), color = c.muted, fontSize = 13.sp)
                        RouteTag(settings.defaultRoute, Modifier.align(Alignment.CenterVertically))
                    }
                }
                Switch(
                    checked = running,
                    onCheckedChange = { on -> if (!on) ShuntVpnService.stop(ctx) else start() },
                    colors = SwitchDefaults.colors(checkedTrackColor = c.accent, checkedThumbColor = c.accentInk),
                )
            }
            if (running) {
                Row(horizontalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                    ShuntButton(
                        if (passLeft > 0) T("End pass") else T("Pass 5 min"),
                        { if (passLeft > 0) VpnState.engine?.pass(0) else confirmPass = true },
                    )
                }
                status?.let {
                    Hint(T("Connections {flows} · blocked {blocked} · DNS names filtered {names}", "flows" to it.optLong("flows"), "blocked" to it.optLong("blocked"), "names" to it.optLong("dns_blocked")))
                }
            }
            if (settings.tunnels.isEmpty()) Hint("No tunnel yet – import one under Tunnels.")
        }

        val ts = status?.optJSONArray("tunnels")
        if (ts != null && ts.length() > 0) {
            Section("Tunnels") {
                for (i in 0 until ts.length()) TunnelCard(ts.getJSONObject(i), status, history, settings.shows("tor.client"))
            }
        }

        if (running) HistorySection(history, range) { range = it }

        status?.optJSONObject("traffic")?.optJSONObject("total")?.let { tot ->
            if ((tot.optJSONObject("total")?.let { it.optLong("rx") + it.optLong("tx") } ?: 0L) > 0L) {
                Section("Traffic", action = { ShuntLink("Reset", { confirmReset = true }) }) {
                    TrafficRows(status.optJSONObject("traffic")!!, ts)
                }
            }
        }

        if (running) {
            Section("Leak test", action = {
                ShuntButton(if (leakRunning) T("Running…") else if (leak == null) T("Run") else T("Run again"), {
                    leakRunning = true
                    Thread { val r = VpnState.engine?.leakTest(); leak = r?.let { JSONArray(it) }; leakRunning = false }.start()
                }, enabled = !leakRunning)
            }) {
                if (leakRunning && torBooting(status)) Hint("Waiting for Tor to start (up to 90 seconds)…")
                leak?.let { rs -> for (i in 0 until rs.length()) LeakRow(rs.getJSONObject(i)) }
                    ?: Hint("Asks api.ipify.org (public IP) and Google DNS (which resolver) through every route.")
            }
        }

        UpdateSection(say)
        AppearanceSection()
        PrivacySection()
    }
    if (confirmPass) {
        AlertDialog(
            onDismissRequest = { confirmPass = false },
            title = { Text(T("Let everything through for 5 minutes?")) },
            text = { Text(T("Your real IP, no tunnels, no blocks, no DNS filter. It ends by itself; connections opened meanwhile are cut then.")) },
            confirmButton = { TextButton({ VpnState.engine?.pass(5); confirmPass = false }) { Text(T("Pass 5 min")) } },
            dismissButton = { TextButton({ confirmPass = false }) { Text(T("Cancel")) } },
        )
    }
    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text(T("Reset traffic statistics?")) },
            text = { Text(T("All monthly and total counts are deleted.")) },
            confirmButton = { TextButton({ VpnState.engine?.resetStats(); confirmReset = false }) { Text(T("Reset")) } },
            dismissButton = { TextButton({ confirmReset = false }) { Text(T("Cancel")) } },
        )
    }
}

@Composable
private fun TunnelCard(t: JSONObject, st: JSONObject, history: History? = null, pro: Boolean = false) {
    val ctx = LocalContext.current
    val h = t.optJSONObject("health")
    val state = h?.optString("state") ?: "unknown"
    val up = t.optBoolean("up")
    val asleep = t.optBoolean("idle") // on demand: made on the first connection
    val boot = t.optInt("bootstrap", 100) // built-in Tor only
    val torStarting = !up && boot in 1..99 && t.optString("error").startsWith("Tor is starting")
    val tone = when {
        asleep || torStarting -> Tone.Neutral
        !up || state == "down" -> Tone.Bad
        state == "stale" -> Tone.Warn
        state == "ok" || state == "idle" -> Tone.Ok
        else -> Tone.Neutral
    }
    EdgeCard(tone) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(t.getString("name"), Modifier.weight(1f).padding(end = Gap.buttons), fontWeight = FontWeight.Bold, fontSize = 15.sp, color = LocalShunt.current.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Pill(
                when {
                    t.optBoolean("idle") -> T("asleep"); torStarting -> T("starting"); !up -> T("down"); state == "ok" -> T("up"); state == "idle" -> T("idle"); state == "stale" -> T("no answers"); state == "down" -> T("down"); else -> T("waiting")
                },
                tone,
            )
        }
        if (boot in 1..99) {
            androidx.compose.material3.LinearProgressIndicator(progress = { boot / 100f }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp), color = LocalShunt.current.accent)
            KV("Tor", "$boot %")
        }
        if (asleep) Hint("Not used right now – saves battery. Connects when an app needs it.")
        else if (torStarting) Unit
        else if (!up) KV("error", t.optString("error"), valueColor = LocalShunt.current.bad)
        else {
            val hs = t.optLong("handshake")
            if (t.optString("type") != "tor") KV("handshake", if (hs == 0L) T("never") else T("{n}s ago", "n" to (st.optLong("time") - hs)))
            val ms = h?.optLong("latency_ms") ?: 0
            val loss = ((h?.optDouble("loss") ?: 0.0) * 100).toInt()
            if (ms > 0) KV("latency", "$ms ms" + if (loss > 0) T(" · {n} % lost", "n" to loss) else "")
            KV("traffic", "↓ ${Formatter.formatShortFileSize(ctx, t.optLong("rx"))} ↑ ${Formatter.formatShortFileSize(ctx, t.optLong("tx"))}")
            Sparkline(history?.tunnel(t.getString("name")), Modifier.padding(top = 8.dp))
        }
        // the Tor the app brings: not through yet (starting, or it failed: the reason is above)
        if (!up && !asleep && t.optString("type") == "tor" && t.has("bootstrap")) {
            Hint("Tor starts together with the app and needs about a minute. If it does not come up, the reason shows here; “Start now” tries again at once.")
            if (pro) ShuntButton("Start now", { Thread { VpnState.engine?.torStart(t.getString("name")) }.start() })
        }
    }
}

/** Month and total per tunnel and for all together (web: TRAFFIC table). */
@Composable
private fun TrafficRows(traffic: JSONObject, tunnels: JSONArray?) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    fun b(o: JSONObject?, k: String) = Formatter.formatShortFileSize(ctx, o?.optLong(k) ?: 0)
    val names = buildList {
        for (i in 0 until (tunnels?.length() ?: 0)) add(tunnels!!.getJSONObject(i).getString("name"))
        add("total")
    }
    Row { listOf("", "this month", "total").forEachIndexed { i, h -> Text(T(h).uppercase(), Modifier.weight(if (i == 0) 1f else 1.3f), color = c.muted, fontSize = 11.sp, fontWeight = FontWeight.SemiBold) } }
    for (n in names) {
        val tr = traffic.optJSONObject(n) ?: continue
        HorizontalDivider(color = c.line)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) { if (n == "total") Text(T("all"), color = c.muted, fontSize = 13.sp) else RouteTag("tunnel:$n") }
            Text("↓ ${b(tr.optJSONObject("month"), "rx")} ↑ ${b(tr.optJSONObject("month"), "tx")}", Modifier.weight(1.3f), fontSize = 12.5.sp, color = c.text)
            Text("↓ ${b(tr.optJSONObject("total"), "rx")} ↑ ${b(tr.optJSONObject("total"), "tx")}", Modifier.weight(1.3f), fontSize = 12.5.sp, color = c.text)
        }
    }
}

/** A built-in Tor that is not through the network yet (the leak test waits for it). */
private fun torBooting(status: JSONObject?): Boolean {
    val ts = status?.optJSONArray("tunnels") ?: return false
    return (0 until ts.length()).any { val t = ts.getJSONObject(it); t.optString("type") == "tor" && !t.optBoolean("up") && t.optInt("bootstrap", 100) in 1..99 }
}

/** The leak test note in the user's language: the daemon's notes are English; "partly working: " carries a detail. */
internal fun leakNote(n: String): String {
    val pre = "partly working: "
    return if (n.startsWith(pre)) T("partly working: {detail}", "detail" to n.removePrefix(pre)) else T(n)
}

@Composable
private fun LeakRow(r: JSONObject) {
    val c = LocalShunt.current
    val v = r.optString("verdict")
    val tone = when (v) { "ok" -> Tone.Ok; "leak" -> Tone.Bad; "warn" -> Tone.Warn; "blocked" -> Tone.Info; "error" -> Tone.Bad; else -> Tone.Neutral }
    val res = r.optJSONObject("result")
    EdgeCard(tone) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RouteTag(r.optString("route"))
            Spacer(Modifier.weight(1f))
            Pill(if (v == "starting") T("starting").uppercase() else v.uppercase(), tone)
        }
        if (v == "starting") KV("Tor", T("Tor is starting: {n} %", "n" to r.optInt("progress")))
        res?.optString("ip")?.takeIf { it.isNotEmpty() }?.let { KV("public IP", it, mono = true) }
        res?.optString("resolver")?.takeIf { it.isNotEmpty() }?.let { KV("DNS resolver", it, mono = true) }
        r.optString("note").takeIf { it.isNotEmpty() }?.let { Text(leakNote(it), color = c.muted, fontSize = 12.sp) }
        r.optString("detail").takeIf { it.isNotEmpty() }?.let { KV("reason", it, valueColor = c.bad) }
    }
}

@Composable
private fun TunnelsScreen(settings: Settings, update: (Settings) -> Unit, say: (String) -> Unit) {
    val ctx = LocalContext.current
    // OpenVPN tunnel that still needs username/password (auth-user-pass)
    var askAuth by remember { mutableStateOf<Tunnel?>(null) }
    val save: (Tunnel, String) -> Unit = { t, note ->
        // first tunnel on a fresh install: "block" as default would leave
        // every app without internet, so the new tunnel becomes the default
        val first = settings.tunnels.isEmpty() && settings.defaultRoute == "block"
        update(settings.copy(
            tunnels = settings.tunnels + t,
            defaultRoute = if (first) "tunnel:${t.name}" else settings.defaultRoute,
        ))
        say(
            (if (first) T("Imported as tunnel:{name}, now the route of all apps (change it under Apps). Restart the VPN to use it.", "name" to t.name)
            else T("Imported as tunnel:{name}. Restart the VPN to use it.", "name" to t.name)) + note
        )
    }
    val add: (String, String) -> Unit = { rawName, text ->
        val name = Store.tunnelName(rawName, settings.tunnels.map { it.name })
        // a wg-quick file always has [Interface]; everything else is tried as .ovpn
        val wg = Regex("""^\s*\[Interface]""", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)).containsMatchIn(text)
        try {
            if (wg) {
                Mobile.checkWireGuard(text)
                save(Tunnel(name, text), "")
            } else {
                val sum = JSONObject(Mobile.checkOpenVPN(text))
                val removed = sum.optJSONArray("removed")?.length() ?: 0
                val t = Tunnel(name, sum.getString("clean"), Tunnel.OPENVPN)
                if (sum.optBoolean("needs_auth")) askAuth = t
                else save(t, if (removed > 0) T(" {n} unsafe lines (scripts etc.) were removed.", "n" to removed) else "")
            }
        } catch (e: Exception) {
            say(T("Not a usable {type} config: {error}", "type" to (if (wg) "WireGuard" else "OpenVPN"), "error" to e.message))
        }
    }
    val scope = rememberCoroutineScope()
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        // cloud providers (Nextcloud etc.) fetch the file over the network: not on the main thread
        scope.launch {
            val picked = withContext(Dispatchers.IO) {
                runCatching {
                    val text = ctx.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                        ?: error(T("file not readable"))
                    var name = "vpn"
                    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                        if (it.moveToFirst()) name = it.getString(0)
                    }
                    name to text
                }
            }
            picked.onSuccess { (name, text) -> add(name, text) }
                .onFailure { say(T("Could not read the file: {error}", "error" to it.message)) }
        }
    }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { add("qr", it) } }
    var confirmDelete by remember { mutableStateOf<Tunnel?>(null) }
    var renaming by remember { mutableStateOf<Tunnel?>(null) }
    val vpnRunning by VpnState.running.collectAsStateWithLifecycle()

    Column(Modifier.verticalScroll(rememberScrollState()).padding(Gap.screen), verticalArrangement = Arrangement.spacedBy(Gap.sections)) {
        Section("Tunnels") {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(Gap.buttons), verticalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                ShuntButton("Import file", { pickFile.launch(arrayOf("*/*")) }, kind = Tone.Ok)
                if (settings.shows("tor.add") && settings.tunnels.none { it.isTor }) ShuntButton("Add Tor", {
                    val conf = if (hasBuiltinTor(ctx)) Tunnel.TOR_BUILTIN_CONF else Tunnel.TOR_DEFAULT_CONF
                    save(Tunnel(Store.tunnelName("tor", settings.tunnels.map { it.name }), conf, Tunnel.TOR), "")
                })
                ShuntButton("Scan QR", {
                    scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("WireGuard or OpenVPN QR code").setBeepEnabled(false))
                })
            }
            if (settings.tunnels.isEmpty()) Hint("A WireGuard file (.conf), an OpenVPN file (.ovpn) or the QR code your VPN server shows.")
            settings.tunnels.forEach { t ->
                val sum = remember(t.conf) {
                    runCatching { JSONObject(if (t.isTor) Mobile.checkTor(t.conf) else if (t.isOpenVPN) Mobile.checkOpenVPN(t.conf) else Mobile.checkWireGuard(t.conf)) }.getOrNull()
                }
                EdgeCard(Tone.Ok) {
                    // the name first: the buttons move below it when the line is too short
                    // large font: buttons below on every card, not on some cards beside the name
                    HeadRow(stack = LocalDensity.current.fontScale > 1.3f,
                        start = {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                                Text(t.name, Modifier.weight(1f, fill = false), fontWeight = FontWeight.Bold, fontSize = 15.sp, color = LocalShunt.current.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(if (t.isTor) "Tor" else if (t.isOpenVPN) "OpenVPN" else "WireGuard", color = LocalShunt.current.muted, fontSize = 12.sp, maxLines = 1)
                            }
                        },
                        end = {
                            Row(horizontalArrangement = Arrangement.spacedBy(Gap.sectionH)) {
                                ShuntLink("Rename", { renaming = t })
                                ShuntLink("Delete", { confirmDelete = t }, color = LocalShunt.current.bad)
                            }
                        },
                    )
                    sum?.let {
                        fun list(k: String) = it.optJSONArray(k)?.let { a -> (0 until a.length()).joinToString(", ") { i -> a.getString(i) } } ?: ""
                        if (t.isTor) {
                            if (it.optString("client") == "builtin") {
                                KV("Tor", T("built in"), mono = true)
                                if (it.optString("bridges").isNotEmpty()) KV("bridges", it.optString("bridges"), mono = true)
                            } else KV("SOCKS", it.optString("socks"), mono = true)
                            it.optString("dns").takeIf { d -> d.isNotEmpty() }?.let { d -> KV("DNS", d, mono = true) }
                            TorHelp(t, builtin = it.optString("client") == "builtin", settings = settings, onSwitch = { c ->
                                update(settings.copy(tunnels = settings.tunnels.map { x -> if (x.name == t.name) x.copy(conf = c) else x }))
                                say(T("Saved. Restart the VPN to use it."))
                            })
                        } else if (t.isOpenVPN) {
                            KV("server", list("remotes"), mono = true)
                            if (t.user.isNotEmpty()) KV("user", t.user, mono = true)
                        } else {
                            KV("address", list("addresses"), mono = true)
                            KV("endpoint", list("endpoints"), mono = true)
                            list("dns").takeIf { d -> d.isNotEmpty() }?.let { d -> KV("DNS", d, mono = true) }
                        }
                        // multi-hop: the tunnel reaches its server through a WireGuard tunnel
                        // (one that goes direct itself and does not run through this one)
                        val carriers = settings.tunnels.filter { !it.isOpenVPN && !it.isTor && it.name != t.name && it.via.isEmpty() }
                            .filter { t.isOpenVPN || settings.tunnels.none { o -> o.via == t.name } }
                            .map { "tunnel:${it.name}" }
                        // Simple hides the choice, but shows it while one is set
                        if (!t.isTor && (t.via.isNotEmpty() || (carriers.isNotEmpty() && settings.shows("tunnel.multihop")))) Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(T("through"), Modifier.width(fontScaled(92.dp)), color = LocalShunt.current.muted, fontSize = 13.sp)
                            RoutePicker(if (t.via.isEmpty()) "direct" else "tunnel:${t.via}", listOf("direct") + carriers) { r ->
                                val via = r.removePrefix("tunnel:").takeIf { r != "direct" } ?: ""
                                update(settings.copy(tunnels = settings.tunnels.map { if (it == t) it.copy(via = via) else it }))
                                say(T("tunnel:{name} now goes {how}. Restart the VPN to use it.", "name" to t.name, "how" to (if (via.isEmpty()) T("directly") else T("through tunnel:{via}", "via" to via))))
                            }
                        }
                    }
                }
            }
        }
        PowerAndDnsSections(settings, update, vpnRunning)
    }
    renaming?.let { t ->
        var text by remember { mutableStateOf(t.name) }
        val others = settings.tunnels.map { it.name } - t.name
        val shown = Store.tunnelName(text, others)
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text(T("Rename tunnel:{name}", "name" to t.name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (vpnRunning) Text(T("Switch the VPN off first: a running tunnel cannot change its name."))
                    else {
                        OutlinedTextField(text, { text = it }, label = { Text(T("New name")) }, singleLine = true)
                        Hint("Letters, digits and \"-\", up to 10. Routes of apps, the default route and tunnels going through this one follow.")
                        if (text.isNotBlank() && shown != text.trim()) Hint(T("Will be saved as \"{name}\".", "name" to shown))
                    }
                }
            },
            confirmButton = {
                TextButton({
                    val to = shown
                    if (to != t.name) {
                        Store.renameStats(ctx, t.name, to)
                        update(Store.rename(settings, t.name, to))
                        say(T("Renamed to tunnel:{name}.", "name" to to))
                    }
                    renaming = null
                }, enabled = !vpnRunning && text.isNotBlank()) { Text(T("Rename")) }
            },
            dismissButton = { TextButton({ renaming = null }) { Text(T("Cancel")) } },
        )
    }
    askAuth?.let { t ->
        var user by remember { mutableStateOf("") }
        var pass by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { askAuth = null },
            title = { Text(T("Login for tunnel:{name}", "name" to t.name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(T("This OpenVPN server asks for a username and password."))
                    OutlinedTextField(user, { user = it }, label = { Text(T("Username")) }, singleLine = true)
                    OutlinedTextField(
                        pass, { pass = it }, label = { Text(T("Password")) }, singleLine = true,
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    )
                }
            },
            confirmButton = {
                TextButton({ save(t.copy(user = user, pass = pass), ""); askAuth = null }, enabled = user.isNotEmpty()) { Text(T("Import")) }
            },
            dismissButton = { TextButton({ askAuth = null }) { Text(T("Cancel")) } },
        )
    }
    confirmDelete?.let { t ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text(T("Delete tunnel:{name}?", "name" to t.name)) },
            text = { Text(T("Apps routed to it are blocked until you pick another route.")) },
            confirmButton = {
                TextButton({
                    val route = "tunnel:${t.name}"
                    update(settings.copy(
                        tunnels = settings.tunnels - t, // OpenVPN tunnels via t stay down (no silent fallback to direct)
                        defaultRoute = if (settings.defaultRoute == route) "block" else settings.defaultRoute,
                        apps = settings.apps.mapValues { (_, r) -> if (r == route) "block" else r },
                        networks = settings.networks.map { if (it.route == route) it.copy(route = "block") else it },
                    ))
                    confirmDelete = null
                }) { Text(T("Delete")) }
            },
            dismissButton = { TextButton({ confirmDelete = null }) { Text(T("Cancel")) } },
        )
    }
}

/** Battery (tunnels on demand) and DNS servers: below the tunnel list. */
@Composable
private fun PowerAndDnsSections(settings: Settings, update: (Settings) -> Unit, vpnRunning: Boolean) {
    val c = LocalShunt.current
    Section("Battery") {
        SwitchRow(
            "Only keep used tunnels connected", settings.onDemand, { update(settings.copy(onDemand = it)) },
            desc = "A tunnel no app uses is closed after a few minutes and opens again on the first connection (about a second).",
        )
        if (settings.onDemand && vpnRunning) Hint("Tunnels that are connected now close once they are unused; asleep ones stay asleep.")
    }
    // Simple hides it, but never while it is on (it must be possible to turn it off);
    // Opsec also puts it on the Status tab
    if (settings.tunnels.any { it.isTor } && (settings.shows("tor.emergency") || settings.torAll)) EmergencySection(settings, update)
    if (settings.shows("dns.servers")) Section("DNS servers") {
        SwitchRow(
            "Ignore the DNS of the tunnels", settings.ignoreTunnelDns, { update(settings.copy(ignoreTunnelDns = it)) },
            desc = "Use only the servers below, not the DNS line of the tunnel files. Names that exist only inside a tunnel (home network) stop resolving.",
        )
        HorizontalDivider(color = c.line)
        Hint(
            if (settings.ignoreTunnelDns) T("These servers are asked, in this order, through the route of the app.")
            else T("Asked after the tunnel's own DNS, when that one does not answer within 2 s.")
        )
        // one block without the section's row gap: the rows are tall already (touch target of "Remove")
        Column { settings.dnsServers.forEach { s ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.beside)) {
                Text(s, Modifier.weight(1f), fontFamily = Mono, fontSize = 14.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    when (s) { "1.1.1.1", "1.0.0.1" -> "Cloudflare"; "8.8.8.8", "8.8.4.4" -> "Google"; "9.9.9.9" -> "Quad9"; else -> "" },
                    color = c.muted, fontSize = 12.sp, maxLines = 1,
                )
                ShuntLink("Remove", { update(settings.copy(dnsServers = settings.dnsServers - s)) }, color = c.bad)
            }
        } }
        var text by remember { mutableStateOf("") }
        val ok = Settings.isDnsAddress(text.trim()) && text.trim() !in settings.dnsServers && settings.dnsServers.size < Settings.MAX_DNS
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.buttons)) {
            OutlinedTextField(
                text, { text = it }, Modifier.weight(1f), label = { Text(T("Add a DNS server (IP)")) }, singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri),
            )
            ShuntButton("Add", { update(settings.copy(dnsServers = settings.dnsServers + text.trim())); text = "" }, kind = Tone.Ok, enabled = ok)
        }
        val missing = Settings.DEFAULT_DNS.filter { it !in settings.dnsServers }
        if (missing.isNotEmpty()) ShuntLink("Add 1.1.1.1 and 8.8.8.8 again", { update(settings.copy(dnsServers = settings.dnsServers + missing)) })
    }
}

internal class AppEntry(val pkg: String, val label: String, val info: ApplicationInfo, val system: Boolean)

/**
 * The app list and its icons, kept for the whole process: asking the package
 * manager for every app (and drawing every icon) each time the tab opens cost
 * battery. Cleared when an app is installed or removed (see [ShuntApp]).
 */
internal object AppCache {
    @Volatile var apps: List<AppEntry>? = null
    val icons = object : android.util.LruCache<String, androidx.compose.ui.graphics.ImageBitmap>(300) {}
    fun clear() { apps = null; icons.evictAll() }
}

@Composable
private fun AppsScreen(settings: Settings, update: (Settings) -> Unit) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    val pm = ctx.packageManager
    var apps by remember { mutableStateOf(AppCache.apps ?: emptyList()) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (AppCache.apps != null) return@LaunchedEffect
        val list = withContext(Dispatchers.IO) {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.packageName != ctx.packageName && pm.checkPermission(Manifest.permission.INTERNET, it.packageName) == PackageManager.PERMISSION_GRANTED }
                .map { AppEntry(it.packageName, pm.getApplicationLabel(it).toString(), it, it.flags and ApplicationInfo.FLAG_SYSTEM != 0 && pm.getLaunchIntentForPackage(it.packageName) == null) }
                .sortedBy { it.label.lowercase() }
        }
        AppCache.apps = list
        apps = list
    }
    Column(Modifier.padding(Gap.screen), verticalArrangement = Arrangement.spacedBy(Gap.sections)) {
        Section("Where traffic goes") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(T("All other apps"), Modifier.weight(1f), color = c.text)
                RoutePicker(settings.defaultRoute, settings.routes()) { update(settings.copy(defaultRoute = it)) }
            }
            // network profiles: another default on Wi-Fi or on mobile data
            for ((link, label) in listOf("wifi" to "… on Wi-Fi", "mobile" to "… on mobile data")) {
                val p = settings.networks.find { it.link == link }
                // Simple hides the network profiles, but shows one while it is set
                if (p == null && !settings.shows("apps.netprofiles")) continue
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(T(label), Modifier.weight(1f).padding(start = 12.dp), color = c.muted)
                    RoutePicker(p?.route ?: SAME, listOf(SAME) + settings.routes().filter { !it.startsWith("link:") }) { r ->
                        val rest = settings.networks.filter { it.link != link }
                        update(settings.copy(networks = if (r == SAME) rest else rest + NetProfile(link, r)))
                    }
                }
            }
            OutlinedTextField(
                query, { query = it }, Modifier.fillMaxWidth(), placeholder = { Text(T("filter…")) }, singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(unfocusedContainerColor = c.panel2, focusedContainerColor = c.panel2, unfocusedBorderColor = c.line),
            )
            CheckRow(showSystem, { showSystem = it }) {
                Text(T("Show system services"), color = c.muted, fontSize = 13.sp)
            }
        }
        LazyColumn(Modifier.weight(1f)) {
            items(apps.filter { (showSystem || !it.system) && (query.isBlank() || it.label.contains(query, true) || it.pkg.contains(query, true)) }, key = { it.pkg }) { a ->
                val icon = remember(a.pkg) {
                    AppCache.icons.get(a.pkg) ?: runCatching { pm.getApplicationIcon(a.info).toBitmap(96, 96).asImageBitmap() }.getOrNull()
                        ?.also { AppCache.icons.put(a.pkg, it) }
                }
                val route = settings.apps[a.pkg]
                // large font: the filter chip and the route go on a line of their own, so names stay readable
                val big = LocalDensity.current.fontScale > 1.3f
                val controls: @Composable () -> Unit = {
                    if (settings.filterLists.isNotEmpty()) {
                        val filtered = a.pkg !in settings.unfiltered
                        FilterChip(filtered, {
                            update(settings.copy(unfiltered = if (filtered) settings.unfiltered + a.pkg else settings.unfiltered - a.pkg))
                        }, label = { Text(T("filter"), fontSize = 12.sp) }, colors = FilterChipDefaults.filterChipColors(
                            containerColor = c.panel, labelColor = c.muted,
                            selectedContainerColor = c.accent.copy(alpha = .18f), selectedLabelColor = c.accent,
                        ))
                        Spacer(Modifier.width(6.dp))
                    }
                    // a column of its own: the filter chips stay lined up whatever the route's length
                    // on a line of its own (large font) the routes start at one left edge
                    Box(Modifier.widthIn(min = fontScaled(104.dp)), contentAlignment = if (big) Alignment.CenterStart else Alignment.CenterEnd) {
                        RoutePicker(route ?: "default", listOf("default") + settings.routes()) { r ->
                            update(settings.copy(apps = if (r == "default") settings.apps - a.pkg else settings.apps + (a.pkg to r)))
                        }
                    }
                }
                Column(Modifier.fillMaxWidth().padding(vertical = 7.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        icon?.let { Image(it, null, Modifier.size(36.dp)) } ?: Spacer(Modifier.size(36.dp))
                        Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                            Text(a.label, maxLines = 1, overflow = TextOverflow.Ellipsis, fontWeight = FontWeight.SemiBold, color = c.text)
                            Text(a.pkg, maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = Mono, fontSize = 11.5.sp, color = c.muted)
                        }
                        if (!big) controls()
                    }
                    if (big) Row(Modifier.fillMaxWidth().padding(start = 46.dp, top = 4.dp), verticalAlignment = Alignment.CenterVertically) { controls() }
                }
                HorizontalDivider(color = c.line)
            }
        }
    }
}

/** DNS filter lists: grouped like on the desktop; on/off, size, source, how many names. */
@Composable
private fun FilterScreen(settings: Settings, update: (Settings) -> Unit, status: JSONObject?) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    var counts by remember { mutableStateOf<Map<String, Int>>(emptyMap()) }
    var bigList by remember { mutableStateOf<Blocklists.Entry?>(null) }
    LaunchedEffect(settings.filterLists) {
        while (true) {
            counts = withContext(Dispatchers.IO) { Blocklists.ALL.keys.associateWith { Blocklists.count(ctx, it) } }
            // a list switched on is downloaded in the background: look again until all are there
            if (settings.filterLists.all { (counts[it] ?: 0) > 0 }) break
            delay(5000)
        }
    }
    fun switchOn(name: String, on: Boolean) {
        val s = settings.copy(filterLists = if (on) settings.filterLists + name else settings.filterLists - name)
        if (on) Thread { if (Blocklists.refresh(ctx, listOf(name))) ShuntVpnService.applyRules(ctx, Store.load(ctx)) }.start()
        update(s)
    }
    Column(Modifier.verticalScroll(rememberScrollState()).padding(Gap.screen), verticalArrangement = Arrangement.spacedBy(Gap.sections)) {
        Section("DNS filter") {
            Hint("Names on these lists get no answer (NXDOMAIN). Per app: Apps → filter. Tap a list's name to see its source.")
            status?.let { Hint(T("{n} names blocked since the VPN started", "n" to it.optLong("dns_blocked"))) }
            val on = Blocklists.ALL.keys.count { it in settings.filterLists }
            Hint(T("{on} of {total} lists on. Big lists (marked) use a lot of mobile data and memory – prefer Wi-Fi.", "on" to on, "total" to Blocklists.ALL.size))
        }
        Blocklists.GROUPS.forEach { (group, entries) ->
            Section(group) {
                entries.forEachIndexed { i, e ->
                    if (i > 0) HorizontalDivider(color = c.line)
                    CheckRow(e.name in settings.filterLists, { checked ->
                        if (checked && e.mb >= Blocklists.BIG_MB) bigList = e else switchOn(e.name, checked)
                    }) {
                        Column(Modifier.weight(1f)) {
                            Text(T(e.what), color = c.text, fontWeight = FontWeight.SemiBold)
                            Text(
                                e.name, fontFamily = Mono, fontSize = 12.sp, color = c.info, textDecoration = TextDecoration.Underline,
                                modifier = Modifier.clickable { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Blocklists.page(e.name)))) },
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            counts[e.name]?.takeIf { it > 0 }?.let { Text(if (it == 1) T("1 name") else T("{n} names", "n" to "%,d".format(it)), color = c.muted, fontSize = 12.sp) }
                            if (e.mb > 0) Text("%.1f MB".format(e.mb), color = if (e.mb >= Blocklists.BIG_MB) c.warn else c.muted, fontSize = 11.sp)
                        }
                    }
                }
            }
        }
        Hint("Lists: HaGeZi (github.com/hagezi/dns-blocklists) and RPiList (github.com/RPiList/specials), refreshed once a day when the VPN starts. Of the HaGeZi all-round lists use one: they build on each other.")
    }
    bigList?.let { e ->
        AlertDialog(
            onDismissRequest = { bigList = null },
            title = { Text(T("Big list")) },
            text = { Text(T("\"{what}\" is about {mb} MB and needs a lot of memory on the phone. Switch it on?", "what" to T(e.what), "mb" to "%.0f".format(e.mb))) },
            confirmButton = { TextButton({ switchOn(e.name, true); bigList = null }) { Text(T("Switch on")) } },
            dismissButton = { TextButton({ bigList = null }) { Text(T("Cancel")) } },
        )
    }
}

/** Network profile not set: the default route above applies. */
private const val SAME = "same as above"

@Composable
private fun RoutePicker(current: String, choices: List<String>, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        Row(Modifier.clickable { open = true }, verticalAlignment = Alignment.CenterVertically) {
            RouteTag(current)
            Text(" ▾", color = LocalShunt.current.muted, fontSize = 12.sp)
        }
        DropdownMenu(open, { open = false }, containerColor = LocalShunt.current.panel2) {
            choices.forEach { r ->
                DropdownMenuItem(text = { RouteTag(r) }, onClick = { open = false; onPick(r) })
            }
        }
    }
}

fun hasBuiltinTor(ctx: android.content.Context) = java.io.File(ctx.applicationInfo.nativeLibraryDir, "libtor.so").exists()

/** The bridge texts for laypeople (the same ones as in the desktop window and `shunt tor help`). */
@Composable
private fun BridgeInfo() {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(T("What is a bridge?"), color = LocalShunt.current.text, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
        Hint("A bridge is a hidden entrance to the Tor network. You only need one if Tor is blocked where you are (for example at school, at work or in a country with censorship). Without a block, use no bridge: that is faster.")
        Hint("snowflake: usually the easiest. Volunteers lend you their internet connection as an entrance. You enter nothing.")
        Hint("obfs4: disguised, so it does not look like Tor. Needs a bridge address from bridges.torproject.org; the built-in ones may be blocked already.")
        Hint("meek: looks like traffic to a big internet service. Works in strict places, but is slow.")
        Hint("Own bridge lines and webtunnel: only in the desktop app for now.")
        Hint("Tip: no censorship, no bridge. Tor blocked: try snowflake first.")
    }
}

/** Tor on the phone: the Tor the app brings, or Orbot (say so, open it or its page with one tap). Buttons only in Pro and Opsec (Levels.TABLE). */
@Composable
private fun TorHelp(t: Tunnel, builtin: Boolean, settings: Settings, onSwitch: (String) -> Unit) {
    val ctx = LocalContext.current
    val pro = settings.shows("tor.client")
    if (builtin) {
        Hint("Tor carries TCP only: no calls, games or QUIC. Tor runs inside The Shunt; every app gets its own circuits. The first start takes a minute.")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(Gap.buttons), verticalArrangement = Arrangement.spacedBy(Gap.buttons)) {
            if (settings.shows("tor.newnym")) ShuntButton("New identity", { Thread { VpnState.engine?.torNewIdentity(t.name) }.start() })
            if (pro) ShuntButton("Use Orbot instead", { onSwitch(Tunnel.TOR_DEFAULT_CONF) })
        }
        if (settings.shows("tor.newnym")) Hint("New identity: Tor builds new routes for new connections, so sites cannot link them to what you did before. Connections that are already open keep their old route.")
        if (settings.shows("tor.bridges") && java.io.File(ctx.applicationInfo.nativeLibraryDir, "liblyrebird.so").exists()) {
            val cur = t.conf.lines().firstOrNull { it.startsWith("bridge") }?.substringAfter("=")?.trim() ?: ""
            var info by remember { mutableStateOf(false) }
            Row(verticalAlignment = Alignment.CenterVertically) {
                // the ⓘ right after the last word, also when the text wraps; tapping the text toggles too
                val accent = LocalShunt.current.accent
                Text(
                    buildAnnotatedString {
                        append(T("Bridges help where Tor is blocked. They are slower."))
                        append(" ")
                        withStyle(SpanStyle(color = accent, fontSize = 16.sp)) { append("ⓘ") }
                    },
                    Modifier.clickable { info = !info }.padding(vertical = 4.dp),
                    color = LocalShunt.current.muted, style = TextStyle(fontSize = 12.5.sp, lineHeight = 1.3.em),
                )
            }
            if (info) BridgeInfo()
            FlowRow(horizontalArrangement = Arrangement.spacedBy(Gap.buttons), verticalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                for ((label, b) in listOf("No bridge" to "", "obfs4" to "obfs4", "snowflake" to "snowflake", "meek" to "meek")) {
                    ShuntButton(label, { onSwitch(Tunnel.TOR_BUILTIN_CONF + if (b.isEmpty()) "" else "bridge = $b\n") }, kind = if (cur == b) Tone.Ok else Tone.Neutral)
                }
            }
        }
        return
    }
    if (!pro) {
        Hint("Tor carries TCP only: no calls, games or QUIC. The Tor client is Orbot – turn on Power User Mode in its settings (so it runs without its own VPN), start it and keep it running.")
        return
    }
    if (hasBuiltinTor(ctx)) ShuntButton("Use the built-in Tor", { onSwitch(Tunnel.TOR_BUILTIN_CONF) })
    val orbot = remember { ctx.packageManager.getLaunchIntentForPackage(Tunnel.ORBOT) }
    Hint("Tor carries TCP only: no calls, games or QUIC. The Tor client is Orbot – turn on Power User Mode in its settings (so it runs without its own VPN), start it and keep it running.")
    if (orbot != null) {
        ShuntButton("Open Orbot", { ctx.startActivity(orbot) })
    } else {
        val fdroid = remember { runCatching { ctx.packageManager.getPackageInfo("org.fdroid.fdroid", 0) }.isSuccess }
        // F-Droid installed: open Orbot's page in it; otherwise the F-Droid website (Play and Orbot's own page are named in the hint)
        ShuntButton("Get Orbot", {
            val web = Intent(Intent.ACTION_VIEW, Uri.parse("https://f-droid.org/packages/org.torproject.android/")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (fdroid) {
                val store = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=org.torproject.android")).setPackage("org.fdroid.fdroid").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                runCatching { ctx.startActivity(store) }.onFailure { ctx.startActivity(web) }
            } else {
                ctx.startActivity(web)
            }
        })
        Hint("Orbot is also on Google Play and on guardianproject.info. If Tor is your default route, the page may not load: pass Orbot or your browser as \"direct\" under Apps, or use a second connection.")
    }
}

/** The emergency switch (everything through Tor); [prominent] = on the Status tab in Opsec, with a red frame. */
@Composable
private fun EmergencySection(settings: Settings, update: (Settings) -> Unit, prominent: Boolean = false) {
    val c = LocalShunt.current
    val hasTor = settings.tunnels.any { it.isTor }
    val m = if (prominent) Modifier.border(2.dp, c.bad, androidx.compose.foundation.shape.RoundedCornerShape(10.dp)) else Modifier
    Section("Emergency", m) {
        if (!hasTor) {
            Hint("The emergency switch needs a Tor tunnel: add one under Tunnels.")
            return@Section
        }
        SwitchRow(
            "Everything through Tor", settings.torAll, { update(settings.copy(torAll = it)) },
            desc = "TCP only: calls and games stop. Turn it off and your routes come back.",
        )
        Hint("For when nothing may leave your device except through Tor: every app goes through the Tor tunnel, whatever its own route says.")
    }
}

/**
 * The findings of the strict check (Opsec) as banners: bad ones always, the
 * warnings (apps going direct) in Pro and Opsec only (Levels "checks.notes").
 */
@Composable
private fun StrictBanners(settings: Settings) {
    val ctx = LocalContext.current
    val noWrap = remember(settings.tunnels) {
        settings.tunnels.filter { it.isOpenVPN }.filter { t ->
            runCatching { !JSONObject(Mobile.checkOpenVPN(t.conf)).optBoolean("tls_wrap") }.getOrDefault(false)
        }.map { it.name }
    }
    val pm = ctx.packageManager
    val fs = remember(settings, noWrap) {
        StrictCheck.findings(settings, noWrap) { pkg -> runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg) }
    }
    fun text(f: Finding) = T(f.msg, *f.args.toTypedArray())
    for (f in fs.filter { it.bad }) Banner(T("Stricter security check"), text(f), bad = true)
    val notes = fs.filter { !it.bad }
    if (notes.isNotEmpty() && settings.shows("checks.notes")) Banner(T("Stricter security check"), notes.joinToString("\n") { "• " + text(it) })
}

/** Settings tab: the level (Simple, Pro, Opsec); switching to and from Opsec runs the Opsec assistant. */
@Composable
private fun SettingsScreen(settings: Settings, update: (Settings) -> Unit) {
    var opsecOn by remember { mutableStateOf(false) }
    var leaveTo by remember { mutableStateOf<Level?>(null) }
    val pick: (Level) -> Unit = { l ->
        when {
            l == settings.level -> Unit
            l == Level.Opsec -> opsecOn = true
            settings.level == Level.Opsec && Opsec.undoable(settings).isNotEmpty() -> leaveTo = l
            else -> update(settings.copy(level = l, opsecUndo = if (settings.level == Level.Opsec) emptyMap() else settings.opsecUndo))
        }
    }
    Column(Modifier.verticalScroll(rememberScrollState()).padding(Gap.screen), verticalArrangement = Arrangement.spacedBy(Gap.sections)) {
        Section("Settings shown") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(Gap.buttons)) {
                for (l in Level.entries) ShuntButton(T(l.label), { pick(l) }, kind = if (settings.level == l) Tone.Ok else Tone.Neutral, modifier = Modifier.weight(1f))
            }
            Hint(
                when (settings.level) {
                    Level.Simple -> T("Simple shows the basics. Tor (adding it, bridges, New identity, Everything through Tor), tunnels through other tunnels, routes per network and the DNS server list are hidden. Tor tunnels you already have stay on their cards. Hidden settings keep working.")
                    Level.Pro -> T("Pro shows everything.")
                    Level.Opsec -> T("Opsec shows everything, marks the app violet, puts the emergency switch on the Status tab and switches on strict settings you confirmed once (switching back offers to undo them).")
                }
            )
        }
    }
    if (opsecOn) OpsecOnDialog(settings, onDone = { s -> opsecOn = false; s?.let(update) })
    leaveTo?.let { to -> OpsecOffDialog(settings, to, onDone = { s -> leaveTo = null; s?.let(update) }) }
}

/** The Opsec list: what it sets, what Android does itself, what is not available here. Nothing changes before "Switch to Opsec". */
@Composable
private fun OpsecOnDialog(settings: Settings, onDone: (Settings?) -> Unit) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    val running by VpnState.running.collectAsStateWithLifecycle()
    val lockdown by VpnState.lockdown.collectAsStateWithLifecycle()
    val privateDns by VpnState.privateDns.collectAsStateWithLifecycle()
    // switches of this app: on by default, except what is set already
    val ticked = remember { mutableStateMapOf<String, Boolean>().apply { for (it in Opsec.ITEMS) if (it.kind == OpsecItem.Kind.SET) put(it.id, true) } }
    AlertDialog(
        onDismissRequest = { onDone(null) },
        title = { Text(T("What Opsec sets")) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(T("Each switch is one setting of this app. Nothing changes before you confirm; switching back to Pro or Simple offers to undo it. Some things only Android can do: they show their state and where to set them."), color = c.text, fontSize = 13.sp)
                for (it in Opsec.ITEMS) {
                    val already = it.kind == OpsecItem.Kind.SET && it.isOn(settings)
                    // state of Android's own settings, when the app can see it
                    val sys: Boolean? = when (it.id) {
                        "killswitch" -> if (running) lockdown else null
                        "privatedns" -> if (running) !privateDns else null
                        else -> null
                    }
                    val note = when (it.kind) {
                        OpsecItem.Kind.SET -> if (already) T("Already set.") + " " + T(it.help) else T(it.help)
                        OpsecItem.Kind.SYSTEM -> T(it.help) + " " + T(it.note) + when (sys) {
                            true -> " " + T("Now: on.")
                            false -> " " + T("Now: off.")
                            null -> if (it.id == "stealth") "" else " " + T("The state shows once the VPN runs.")
                        }
                        OpsecItem.Kind.BUILTIN -> T(it.note) + " " + T(it.help)
                        OpsecItem.Kind.NA -> T(it.note)
                    }
                    CheckRow(
                        checked = when (it.kind) {
                            OpsecItem.Kind.SET -> already || ticked[it.id] == true
                            OpsecItem.Kind.SYSTEM -> sys == true
                            OpsecItem.Kind.BUILTIN -> true
                            OpsecItem.Kind.NA -> false
                        },
                        onChange = { on -> ticked[it.id] = on },
                        enabled = it.kind == OpsecItem.Kind.SET && !already,
                        top = true,
                    ) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(T(it.text), color = if (it.kind == OpsecItem.Kind.NA) c.muted else c.text, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                            Text(note, color = c.muted, fontSize = 12.sp)
                            when (it.id) {
                                "killswitch" -> if (sys != true) ShuntLink("Open VPN settings", { ctx.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }, compact = true)
                                "privatedns" -> if (sys != true) ShuntLink("Open network settings", { ctx.startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)) }, compact = true)
                            }
                        }
                    }
                }
                Text(T("Opsec is no guarantee."), color = c.text, fontWeight = FontWeight.Bold)
                Text(T("These settings close common leaks of this phone; they do not make you anonymous. Your VPN provider still sees your traffic, and websites still recognise you by logins, cookies and your browser."), color = c.text, fontSize = 13.sp)
                if (settings.defaultRoute.startsWith("direct") || settings.defaultRoute.startsWith("link:")) {
                    Text(T("All other apps go direct, past every tunnel. Opsec does not change that for you: choose a tunnel under Apps → “All other apps”."), color = c.warn, fontSize = 13.sp)
                }
            }
        },
        confirmButton = { TextButton({ onDone(Opsec.switchOn(settings, ticked.filterValues { it }.keys)) }) { Text(T("Switch to Opsec")) } },
        dismissButton = { TextButton({ onDone(null) }) { Text(T("Cancel")) } },
    )
}

/** Leaving Opsec: offer to put back what Opsec changed (ticked = back to how it was). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun OpsecOffDialog(settings: Settings, to: Level, onDone: (Settings?) -> Unit) {
    val c = LocalShunt.current
    val items = Opsec.undoable(settings)
    val ticked = remember { mutableStateMapOf<String, Boolean>().apply { for (it in items) put(it.id, true) } }
    // a plain dialog: three buttons do not fit AlertDialog's button row, which then leaves big gaps
    BasicAlertDialog(onDismissRequest = { onDone(null) }) {
        Surface(shape = AlertDialogDefaults.shape, color = AlertDialogDefaults.containerColor, tonalElevation = AlertDialogDefaults.TonalElevation) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(T("Undo the Opsec settings?"), style = MaterialTheme.typography.headlineSmall, color = AlertDialogDefaults.titleContentColor)
                Spacer(Modifier.height(8.dp))
                Text(T("Opsec changed these settings. Ticked ones go back to how they were before; the others stay as they are."), color = c.text, fontSize = 13.sp)
                for (it in items) CheckRow(ticked[it.id] == true, { on -> ticked[it.id] = on }, top = true) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(T(it.text), color = c.text, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        Text(T("Set by Opsec. Ticked: back to how it was before."), color = c.muted, fontSize = 12.sp)
                    }
                }
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.End) {
                    TextButton({ onDone(Opsec.switchOff(settings, to, ticked.filterValues { it }.keys)) }) { Text(T("Undo ticked ones")) }
                    Row {
                        TextButton({ onDone(null) }) { Text(T("Cancel")) }
                        TextButton({ onDone(Opsec.switchOff(settings, to, emptySet())) }) { Text(T("Keep all")) }
                    }
                }
            }
        }
    }
}
