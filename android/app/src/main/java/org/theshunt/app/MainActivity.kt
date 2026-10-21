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
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
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
                Surface(Modifier.fillMaxSize(), color = LocalShunt.current.bg) { App() }
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
    val c = LocalShunt.current

    Scaffold(
        containerColor = c.bg,
        topBar = { Header(status) },
        bottomBar = {
            NavigationBar(containerColor = c.panel) {
                val filterIcon = painterResource(R.drawable.ic_tab_filter)
                listOf(
                    "Status" to rememberVectorPainter(Icons.Filled.Home), "Tunnels" to rememberVectorPainter(Icons.Filled.Lock),
                    "Apps" to rememberVectorPainter(Icons.AutoMirrored.Filled.List), "Filter" to filterIcon,
                ).forEachIndexed { i, (label, icon) ->
                    NavigationBarItem(
                        selected = tab == i, onClick = { tab = i }, icon = { Icon(icon, null) },
                        label = { Text(label, fontWeight = if (tab == i) FontWeight.Bold else FontWeight.Normal) },
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
                0 -> StatusScreen(settings, status) { message = it }
                1 -> TunnelsScreen(settings, update) { message = it }
                2 -> AppsScreen(settings, update)
                3 -> FilterScreen(settings, update, status)
            }
        }
    }
    message?.let {
        AlertDialog(onDismissRequest = { message = null }, confirmButton = { TextButton({ message = null }) { Text("OK") } }, text = { Text(it) })
    }
}

/** Sticky header like the web UI: logo, state pill, PANIC. */
@Composable
private fun Header(status: JSONObject?) {
    val c = LocalShunt.current
    val running by VpnState.running.collectAsStateWithLifecycle()
    val lockdown by VpnState.lockdown.collectAsStateWithLifecycle()
    val ov = status?.optJSONObject("override")
    val panic = ov?.optBoolean("panic") ?: false
    val passLeft = ov?.optLong("pass_left") ?: 0L
    Column(Modifier.background(c.bg).statusBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            ShuntLogo()
            Spacer(Modifier.width(10.dp))
            Text("The Shunt", fontWeight = FontWeight.Bold, fontSize = 17.sp, color = c.text)
            Spacer(Modifier.width(12.dp))
            when {
                !running -> Pill("off")
                panic -> Pill("PANIC", Tone.Bad)
                passLeft > 0 -> Pill("PASS %d:%02d".format(passLeft / 60, passLeft % 60), Tone.Bad)
                !lockdown -> Pill("no kill switch", Tone.Warn)
                else -> Pill("protected", Tone.Ok)
            }
            Spacer(Modifier.weight(1f))
            if (running) {
                ShuntButton(if (panic) "Release" else "PANIC", {
                    VpnState.engine?.setPanic(!panic)
                }, kind = Tone.Bad)
            }
        }
        HorizontalDivider(color = c.line)
    }
}

@Composable
private fun StatusScreen(settings: Settings, status: JSONObject?, say: (String) -> Unit) {
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
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        error?.let { Banner("VPN error", it, bad = true) }
        if (panic) Banner("Panic", "Everything is blocked, running connections were cut.", bad = true)
        else if (passLeft > 0) Banner(
            "Pass – unprotected",
            "Everything goes direct: your real IP, no tunnels, no blocks, no DNS filter. Connections opened meanwhile are cut when it ends.",
            bad = true,
        ) { TextButton({ VpnState.engine?.pass(0) }) { Text("End pass now") } }
        if (running && !lockdown) {
            // the only real kill switch on Android is the system's: without
            // it, apps get out unprotected while the VPN (re)starts or crashes
            Banner(
                "No kill switch",
                "While the VPN starts, restarts or crashes, apps can get out unprotected. " +
                    "Turn on \"Always-on VPN\" and \"Block connections without VPN\" for The Shunt.",
            ) { TextButton({ ctx.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }) { Text("Open VPN settings") } }
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
                "Android sends DNS for all apps to its \"Private DNS\" server, past the tunnels and the DNS filter. " +
                    "Set Private DNS to \"Off\" so every app resolves through its route.",
            ) { TextButton({ ctx.startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)) }) { Text("Open network settings") } }
        }

        Section("VPN") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(if (running) "On" else "Off", fontWeight = FontWeight.Bold, color = c.text)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("default route ", color = c.muted, fontSize = 13.sp)
                        RouteTag(settings.defaultRoute)
                    }
                }
                Switch(
                    checked = running,
                    onCheckedChange = { on -> if (!on) ShuntVpnService.stop(ctx) else start() },
                    colors = SwitchDefaults.colors(checkedTrackColor = c.accent, checkedThumbColor = c.accentInk),
                )
            }
            if (running) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ShuntButton(
                        if (passLeft > 0) "End pass" else "Pass 5 min",
                        { if (passLeft > 0) VpnState.engine?.pass(0) else confirmPass = true },
                    )
                }
                status?.let {
                    Hint("Connections ${it.optLong("flows")} · blocked ${it.optLong("blocked")} · DNS names filtered ${it.optLong("dns_blocked")}")
                }
            }
            if (settings.tunnels.isEmpty()) Hint("No tunnel yet – import one under Tunnels.")
        }

        val ts = status?.optJSONArray("tunnels")
        if (ts != null && ts.length() > 0) {
            Section("Tunnels") {
                for (i in 0 until ts.length()) TunnelCard(ts.getJSONObject(i), status, history)
            }
        }

        if (running) HistorySection(history, range) { range = it }

        status?.optJSONObject("traffic")?.optJSONObject("total")?.let { tot ->
            if ((tot.optJSONObject("total")?.let { it.optLong("rx") + it.optLong("tx") } ?: 0L) > 0L) {
                Section("Traffic", action = { TextButton({ confirmReset = true }) { Text("Reset") } }) {
                    TrafficRows(status.optJSONObject("traffic")!!, ts)
                }
            }
        }

        if (running) {
            Section("Leak test", action = {
                ShuntButton(if (leakRunning) "Running…" else if (leak == null) "Run" else "Run again", {
                    leakRunning = true
                    Thread { val r = VpnState.engine?.leakTest(); leak = r?.let { JSONArray(it) }; leakRunning = false }.start()
                }, enabled = !leakRunning)
            }) {
                leak?.let { rs -> for (i in 0 until rs.length()) LeakRow(rs.getJSONObject(i)) }
                    ?: Hint("Asks api.ipify.org (public IP) and Google DNS (which resolver) through every route.")
            }
        }

        UpdateSection(say)
        AppearanceSection()
    }
    if (confirmPass) {
        AlertDialog(
            onDismissRequest = { confirmPass = false },
            title = { Text("Let everything through for 5 minutes?") },
            text = { Text("Your real IP, no tunnels, no blocks, no DNS filter. It ends by itself; connections opened meanwhile are cut then.") },
            confirmButton = { TextButton({ VpnState.engine?.pass(5); confirmPass = false }) { Text("Pass 5 min") } },
            dismissButton = { TextButton({ confirmPass = false }) { Text("Cancel") } },
        )
    }
    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Reset traffic statistics?") },
            text = { Text("All monthly and total counts are deleted.") },
            confirmButton = { TextButton({ VpnState.engine?.resetStats(); confirmReset = false }) { Text("Reset") } },
            dismissButton = { TextButton({ confirmReset = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun TunnelCard(t: JSONObject, st: JSONObject, history: History? = null) {
    val ctx = LocalContext.current
    val h = t.optJSONObject("health")
    val state = h?.optString("state") ?: "unknown"
    val up = t.optBoolean("up")
    val asleep = t.optBoolean("idle") // on demand: made on the first connection
    val tone = when {
        asleep -> Tone.Neutral
        !up || state == "down" -> Tone.Bad
        state == "stale" -> Tone.Warn
        state == "ok" || state == "idle" -> Tone.Ok
        else -> Tone.Neutral
    }
    EdgeCard(tone) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(t.getString("name"), Modifier.weight(1f), fontWeight = FontWeight.Bold, fontSize = 15.sp, color = LocalShunt.current.text)
            Pill(
                when {
                    t.optBoolean("idle") -> "asleep"; !up -> "down"; state == "ok" -> "up"; state == "idle" -> "idle"; state == "stale" -> "no answers"; state == "down" -> "down"; else -> "waiting"
                },
                tone,
            )
        }
        if (asleep) Hint("Not used right now – saves battery. Connects when an app needs it.")
        else if (!up) KV("error", t.optString("error"), valueColor = LocalShunt.current.bad)
        else {
            val hs = t.optLong("handshake")
            KV("handshake", if (hs == 0L) "never" else "${st.optLong("time") - hs}s ago")
            val ms = h?.optLong("latency_ms") ?: 0
            val loss = ((h?.optDouble("loss") ?: 0.0) * 100).toInt()
            if (ms > 0) KV("latency", "$ms ms" + if (loss > 0) " · $loss % lost" else "")
            KV("traffic", "↓ ${Formatter.formatShortFileSize(ctx, t.optLong("rx"))} ↑ ${Formatter.formatShortFileSize(ctx, t.optLong("tx"))}")
            Sparkline(history?.tunnel(t.getString("name")), Modifier.padding(top = 8.dp))
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
    Row { listOf("", "this month", "total").forEachIndexed { i, h -> Text(h.uppercase(), Modifier.weight(if (i == 0) 1f else 1.3f), color = c.muted, fontSize = 11.sp, fontWeight = FontWeight.SemiBold) } }
    for (n in names) {
        val tr = traffic.optJSONObject(n) ?: continue
        HorizontalDivider(color = c.line)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) { if (n == "total") Text("all", color = c.muted, fontSize = 13.sp) else RouteTag("tunnel:$n") }
            Text("↓ ${b(tr.optJSONObject("month"), "rx")} ↑ ${b(tr.optJSONObject("month"), "tx")}", Modifier.weight(1.3f), fontSize = 12.5.sp, color = c.text)
            Text("↓ ${b(tr.optJSONObject("total"), "rx")} ↑ ${b(tr.optJSONObject("total"), "tx")}", Modifier.weight(1.3f), fontSize = 12.5.sp, color = c.text)
        }
    }
}

@Composable
private fun LeakRow(r: JSONObject) {
    val c = LocalShunt.current
    val v = r.optString("verdict")
    val tone = when (v) { "ok" -> Tone.Ok; "leak" -> Tone.Bad; "warn" -> Tone.Warn; "blocked" -> Tone.Info; else -> Tone.Neutral }
    val res = r.optJSONObject("result")
    EdgeCard(tone) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RouteTag(r.optString("route"))
            Spacer(Modifier.weight(1f))
            Pill(v.uppercase(), tone)
        }
        res?.optString("ip")?.takeIf { it.isNotEmpty() }?.let { KV("public IP", it, mono = true) }
        res?.optString("resolver")?.takeIf { it.isNotEmpty() }?.let { KV("DNS resolver", it, mono = true) }
        r.optString("note").takeIf { it.isNotEmpty() }?.let { Text(it, color = c.muted, fontSize = 12.sp) }
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
            (if (first) "Imported as tunnel:${t.name}, now the route of all apps (change it under Apps). Restart the VPN to use it."
            else "Imported as tunnel:${t.name}. Restart the VPN to use it.") + note
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
                else save(t, if (removed > 0) " $removed unsafe lines (scripts etc.) were removed." else "")
            }
        } catch (e: Exception) {
            say("Not a usable ${if (wg) "WireGuard" else "OpenVPN"} config: ${e.message}")
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
                        ?: error("file not readable")
                    var name = "vpn"
                    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                        if (it.moveToFirst()) name = it.getString(0)
                    }
                    name to text
                }
            }
            picked.onSuccess { (name, text) -> add(name, text) }
                .onFailure { say("Could not read the file: ${it.message}") }
        }
    }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { add("qr", it) } }
    var confirmDelete by remember { mutableStateOf<Tunnel?>(null) }
    var renaming by remember { mutableStateOf<Tunnel?>(null) }
    val vpnRunning by VpnState.running.collectAsStateWithLifecycle()

    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Section("Tunnels") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ShuntButton("Import file", { pickFile.launch(arrayOf("*/*")) }, kind = Tone.Ok)
                ShuntButton("Scan QR", {
                    scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("WireGuard or OpenVPN QR code").setBeepEnabled(false))
                })
            }
            if (settings.tunnels.isEmpty()) Hint("A WireGuard file (.conf), an OpenVPN file (.ovpn) or the QR code your VPN server shows.")
            settings.tunnels.forEach { t ->
                val sum = remember(t.conf) {
                    runCatching { JSONObject(if (t.isOpenVPN) Mobile.checkOpenVPN(t.conf) else Mobile.checkWireGuard(t.conf)) }.getOrNull()
                }
                EdgeCard(Tone.Ok) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(t.name, Modifier.weight(1f), fontWeight = FontWeight.Bold, fontSize = 15.sp, color = LocalShunt.current.text)
                        Pill(if (t.isOpenVPN) "OpenVPN" else "WireGuard", Tone.Neutral)
                        TextButton({ renaming = t }) { Text("Rename") }
                        TextButton({ confirmDelete = t }) { Text("Delete", color = LocalShunt.current.bad) }
                    }
                    sum?.let {
                        fun list(k: String) = it.optJSONArray(k)?.let { a -> (0 until a.length()).joinToString(", ") { i -> a.getString(i) } } ?: ""
                        if (t.isOpenVPN) {
                            KV("server", list("remotes"), mono = true)
                            if (t.user.isNotEmpty()) KV("user", t.user, mono = true)
                            // multi-hop: openvpn reaches its server through a WireGuard tunnel
                            val carriers = settings.tunnels.filter { !it.isOpenVPN }.map { "tunnel:${it.name}" }
                            if (carriers.isNotEmpty()) Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("through", Modifier.weight(1f), color = LocalShunt.current.muted, fontSize = 13.sp)
                                RoutePicker(if (t.via.isEmpty()) "direct" else "tunnel:${t.via}", listOf("direct") + carriers) { r ->
                                    val via = r.removePrefix("tunnel:").takeIf { r != "direct" } ?: ""
                                    update(settings.copy(tunnels = settings.tunnels.map { if (it == t) it.copy(via = via) else it }))
                                    say("tunnel:${t.name} now goes ${if (via.isEmpty()) "directly" else "through tunnel:$via"}. Restart the VPN to use it.")
                                }
                            }
                        } else {
                            KV("address", list("addresses"), mono = true)
                            KV("endpoint", list("endpoints"), mono = true)
                            list("dns").takeIf { d -> d.isNotEmpty() }?.let { d -> KV("DNS", d, mono = true) }
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
            title = { Text("Rename tunnel:${t.name}") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (vpnRunning) Text("Switch the VPN off first: a running tunnel cannot change its name.")
                    else {
                        OutlinedTextField(text, { text = it }, label = { Text("New name") }, singleLine = true)
                        Hint("Letters, digits and \"-\", up to 10. Routes of apps, the default route and tunnels going through this one follow.")
                        if (text.isNotBlank() && shown != text.trim()) Hint("Will be saved as \"$shown\".")
                    }
                }
            },
            confirmButton = {
                TextButton({
                    val to = shown
                    if (to != t.name) {
                        Store.renameStats(ctx, t.name, to)
                        update(Store.rename(settings, t.name, to))
                        say("Renamed to tunnel:$to.")
                    }
                    renaming = null
                }, enabled = !vpnRunning && text.isNotBlank()) { Text("Rename") }
            },
            dismissButton = { TextButton({ renaming = null }) { Text("Cancel") } },
        )
    }
    askAuth?.let { t ->
        var user by remember { mutableStateOf("") }
        var pass by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { askAuth = null },
            title = { Text("Login for tunnel:${t.name}") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("This OpenVPN server asks for a username and password.")
                    OutlinedTextField(user, { user = it }, label = { Text("Username") }, singleLine = true)
                    OutlinedTextField(
                        pass, { pass = it }, label = { Text("Password") }, singleLine = true,
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    )
                }
            },
            confirmButton = {
                TextButton({ save(t.copy(user = user, pass = pass), ""); askAuth = null }, enabled = user.isNotEmpty()) { Text("Import") }
            },
            dismissButton = { TextButton({ askAuth = null }) { Text("Cancel") } },
        )
    }
    confirmDelete?.let { t ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete tunnel:${t.name}?") },
            text = { Text("Apps routed to it are blocked until you pick another route.") },
            confirmButton = {
                TextButton({
                    val route = "tunnel:${t.name}"
                    update(settings.copy(
                        tunnels = settings.tunnels - t, // OpenVPN tunnels via t stay down (no silent fallback to direct)
                        defaultRoute = if (settings.defaultRoute == route) "block" else settings.defaultRoute,
                        apps = settings.apps.mapValues { (_, r) -> if (r == route) "block" else r },
                    ))
                    confirmDelete = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton({ confirmDelete = null }) { Text("Cancel") } },
        )
    }
}

/** Battery (tunnels on demand) and DNS servers: below the tunnel list. */
@Composable
private fun PowerAndDnsSections(settings: Settings, update: (Settings) -> Unit, vpnRunning: Boolean) {
    val c = LocalShunt.current
    Section("Battery") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Only keep used tunnels connected", color = c.text, fontWeight = FontWeight.SemiBold)
                Text("A tunnel no app uses is closed after a few minutes and opens again on the first connection (about a second).", color = c.muted, fontSize = 12.sp)
            }
            Switch(settings.onDemand, { update(settings.copy(onDemand = it)) })
        }
        if (settings.onDemand && vpnRunning) Hint("Tunnels that are connected now close once they are unused; asleep ones stay asleep.")
    }
    Section("DNS servers") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Ignore the DNS of the tunnels", color = c.text, fontWeight = FontWeight.SemiBold)
                Text("Use only the servers below, not the DNS line of the tunnel files. Names that exist only inside a tunnel (home network) stop resolving.", color = c.muted, fontSize = 12.sp)
            }
            Switch(settings.ignoreTunnelDns, { update(settings.copy(ignoreTunnelDns = it)) })
        }
        HorizontalDivider(color = c.line)
        Hint(
            if (settings.ignoreTunnelDns) "These servers are asked, in this order, through the route of the app."
            else "Asked after the tunnel's own DNS, when that one does not answer within 2 s."
        )
        settings.dnsServers.forEach { s ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(s, Modifier.weight(1f), fontFamily = Mono, color = c.text)
                Text(
                    when (s) { "1.1.1.1", "1.0.0.1" -> "Cloudflare"; "8.8.8.8", "8.8.4.4" -> "Google"; "9.9.9.9" -> "Quad9"; else -> "" },
                    color = c.muted, fontSize = 12.sp,
                )
                TextButton({ update(settings.copy(dnsServers = settings.dnsServers - s)) }) { Text("Remove", color = c.bad) }
            }
        }
        var text by remember { mutableStateOf("") }
        val ok = Settings.isDnsAddress(text.trim()) && text.trim() !in settings.dnsServers && settings.dnsServers.size < Settings.MAX_DNS
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                text, { text = it }, Modifier.weight(1f), label = { Text("Add a DNS server (IP)") }, singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri),
            )
            ShuntButton("Add", { update(settings.copy(dnsServers = settings.dnsServers + text.trim())); text = "" }, kind = Tone.Ok, enabled = ok)
        }
        val missing = Settings.DEFAULT_DNS.filter { it !in settings.dnsServers }
        if (missing.isNotEmpty()) TextButton({ update(settings.copy(dnsServers = settings.dnsServers + missing)) }) { Text("Add 1.1.1.1 and 8.8.8.8 again") }
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
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Section("Where traffic goes") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("All other apps", Modifier.weight(1f), color = c.text)
                RoutePicker(settings.defaultRoute, settings.routes()) { update(settings.copy(defaultRoute = it)) }
            }
            OutlinedTextField(
                query, { query = it }, Modifier.fillMaxWidth(), placeholder = { Text("filter…") }, singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(unfocusedContainerColor = c.panel2, focusedContainerColor = c.panel2, unfocusedBorderColor = c.line),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(showSystem, { showSystem = it })
                Text("Show system services", color = c.muted, fontSize = 13.sp)
            }
        }
        LazyColumn(Modifier.weight(1f)) {
            items(apps.filter { (showSystem || !it.system) && (query.isBlank() || it.label.contains(query, true) || it.pkg.contains(query, true)) }, key = { it.pkg }) { a ->
                val icon = remember(a.pkg) {
                    AppCache.icons.get(a.pkg) ?: runCatching { pm.getApplicationIcon(a.info).toBitmap(96, 96).asImageBitmap() }.getOrNull()
                        ?.also { AppCache.icons.put(a.pkg, it) }
                }
                val route = settings.apps[a.pkg]
                Row(Modifier.fillMaxWidth().padding(vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
                    icon?.let { Image(it, null, Modifier.size(36.dp)) } ?: Spacer(Modifier.size(36.dp))
                    Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                        Text(a.label, maxLines = 1, fontWeight = FontWeight.SemiBold, color = c.text)
                        Text(a.pkg, maxLines = 1, fontFamily = Mono, fontSize = 11.5.sp, color = c.muted)
                    }
                    if (settings.filterLists.isNotEmpty()) {
                        val filtered = a.pkg !in settings.unfiltered
                        FilterChip(filtered, {
                            update(settings.copy(unfiltered = if (filtered) settings.unfiltered + a.pkg else settings.unfiltered - a.pkg))
                        }, label = { Text("filter", fontSize = 12.sp) }, colors = FilterChipDefaults.filterChipColors(
                            containerColor = c.panel, labelColor = c.muted,
                            selectedContainerColor = c.accent.copy(alpha = .18f), selectedLabelColor = c.accent,
                        ))
                        Spacer(Modifier.width(6.dp))
                    }
                    RoutePicker(route ?: "default", listOf("default") + settings.routes()) { r ->
                        update(settings.copy(apps = if (r == "default") settings.apps - a.pkg else settings.apps + (a.pkg to r)))
                    }
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
    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Section("DNS filter") {
            Hint("Names on these lists get no answer (NXDOMAIN). Per app: Apps → filter. Tap a list's name to see its source.")
            status?.let { Hint("${it.optLong("dns_blocked")} names blocked since the VPN started") }
            val on = Blocklists.ALL.keys.count { it in settings.filterLists }
            Hint("$on of ${Blocklists.ALL.size} lists on. Big lists (marked) use a lot of mobile data and memory – prefer Wi-Fi.")
        }
        Blocklists.GROUPS.forEach { (group, entries) ->
            Section(group) {
                entries.forEachIndexed { i, e ->
                    if (i > 0) HorizontalDivider(color = c.line)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(e.name in settings.filterLists, { checked ->
                            if (checked && e.mb >= Blocklists.BIG_MB) bigList = e else switchOn(e.name, checked)
                        })
                        Column(Modifier.weight(1f)) {
                            Text(e.what, color = c.text, fontWeight = FontWeight.SemiBold)
                            Text(
                                e.name, fontFamily = Mono, fontSize = 12.sp, color = c.info, textDecoration = TextDecoration.Underline,
                                modifier = Modifier.clickable { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Blocklists.page(e.name)))) },
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            counts[e.name]?.takeIf { it > 0 }?.let { Text(if (it == 1) "1 name" else "%,d names".format(it), color = c.muted, fontSize = 12.sp) }
                            if (e.mb > 0) Text("%.1f MB".format(e.mb), color = if (e.mb >= Blocklists.BIG_MB) c.warn else c.muted, fontSize = 11.sp)
                        }
                    }
                }
            }
        }
        Hint("Lists: RPiList (github.com/RPiList/specials), refreshed once a day when the VPN starts.")
    }
    bigList?.let { e ->
        AlertDialog(
            onDismissRequest = { bigList = null },
            title = { Text("Big list") },
            text = { Text("\"${e.what}\" is about %.0f MB and needs a lot of memory on the phone. Switch it on?".format(e.mb)) },
            confirmButton = { TextButton({ switchOn(e.name, true); bigList = null }) { Text("Switch on") } },
            dismissButton = { TextButton({ bigList = null }) { Text("Cancel") } },
        )
    }
}

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
