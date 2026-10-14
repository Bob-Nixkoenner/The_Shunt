package org.theshunt.app

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.format.Formatter
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.theshunt.mobile.Mobile

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkThemeCompat()) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) { App() }
            }
        }
    }

    private fun isSystemInDarkThemeCompat(): Boolean =
        (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES
}

@Composable
private fun App() {
    val ctx = LocalContext.current
    var settings by remember { mutableStateOf(Store.load(ctx)) }
    var tab by remember { mutableIntStateOf(0) }
    var message by remember { mutableStateOf<String?>(null) }
    val update: (Settings) -> Unit = { s ->
        settings = s
        Store.save(ctx, s)
        ShuntVpnService.applyRules(ctx, s)?.let { message = it }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                listOf("Status", "Tunnels", "Apps").forEachIndexed { i, label ->
                    NavigationBarItem(selected = tab == i, onClick = { tab = i }, icon = {}, label = { Text(label) })
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) {
                0 -> StatusScreen(settings, update)
                1 -> TunnelsScreen(settings, update) { message = it }
                2 -> AppsScreen(settings, update)
            }
        }
    }
    message?.let {
        AlertDialog(onDismissRequest = { message = null }, confirmButton = { TextButton({ message = null }) { Text("OK") } }, text = { Text(it) })
    }
}

@Composable
private fun StatusScreen(settings: Settings, update: (Settings) -> Unit) {
    val ctx = LocalContext.current
    val running by VpnState.running.collectAsStateWithLifecycle()
    val error by VpnState.error.collectAsStateWithLifecycle()
    var status by remember { mutableStateOf<JSONObject?>(null) }
    val askPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) ShuntVpnService.start(ctx)
    }
    LaunchedEffect(running) {
        while (running) {
            status = VpnState.engine?.status()?.let { JSONObject(it) }
            delay(2000)
        }
        status = null
    }
    Column(Modifier.padding(16.dp).fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("The Shunt", style = MaterialTheme.typography.headlineMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (running) "VPN on" else "VPN off", Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
            Switch(checked = running, onCheckedChange = { on ->
                if (!on) ShuntVpnService.stop(ctx)
                else {
                    val intent = VpnService.prepare(ctx)
                    if (intent != null) askPermission.launch(intent) else ShuntVpnService.start(ctx)
                }
            })
        }
        error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
        Text("Default route: ${settings.defaultRoute}", style = MaterialTheme.typography.bodyMedium)
        if (settings.tunnels.isEmpty()) Text("No tunnel yet – import one under Tunnels.")
        status?.let { st ->
            Text("Connections: ${st.optLong("flows")}, blocked: ${st.optLong("blocked")}, DNS names filtered: ${st.optLong("dns_blocked")}")
            val ts = st.optJSONArray("tunnels")
            for (i in 0 until (ts?.length() ?: 0)) {
                val t = ts!!.getJSONObject(i)
                val hs = t.optLong("handshake")
                val ago = if (hs == 0L) "no handshake" else "handshake ${st.optLong("time") - hs}s ago"
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        val h = t.optJSONObject("health")
                        val state = h?.optString("state") ?: "unknown"
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("tunnel:${t.getString("name")}", Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
                            Text(
                                when (state) {
                                    "ok" -> "● ok"; "idle" -> "● idle"; "stale" -> "● no answers"; "down" -> "● down"; else -> "● …"
                                },
                                color = when (state) {
                                    "ok" -> androidx.compose.ui.graphics.Color(0xFF2E7D32)
                                    "stale" -> androidx.compose.ui.graphics.Color(0xFFF9A825)
                                    "down" -> MaterialTheme.colorScheme.error
                                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                                },
                                style = MaterialTheme.typography.labelMedium,
                            )
                        }
                        if (!t.optBoolean("up")) Text("down: ${t.optString("error")}", color = MaterialTheme.colorScheme.error)
                        else {
                            Text("$ago · ↓ ${Formatter.formatShortFileSize(ctx, t.optLong("rx"))} ↑ ${Formatter.formatShortFileSize(ctx, t.optLong("tx"))}")
                            val ms = h?.optLong("latency_ms") ?: 0
                            val loss = ((h?.optDouble("loss") ?: 0.0) * 100).toInt()
                            if (ms > 0) Text("latency $ms ms" + if (loss > 0) " · $loss % lost" else "", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
        HorizontalDivider()
        Text("DNS filter", style = MaterialTheme.typography.titleMedium)
        Text("Names on these lists get no answer (NXDOMAIN). Per app: Apps → filter.", style = MaterialTheme.typography.bodySmall)
        Blocklists.ALL.forEach { (name, what) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(name in settings.filterLists, { on ->
                    val s = settings.copy(filterLists = if (on) settings.filterLists + name else settings.filterLists - name)
                    if (on) Thread { if (Blocklists.refresh(ctx, listOf(name))) ShuntVpnService.applyRules(ctx, Store.load(ctx)) }.start()
                    update(s)
                })
                Text("$what ($name)")
            }
        }
    }
}

@Composable
private fun TunnelsScreen(settings: Settings, update: (Settings) -> Unit, say: (String) -> Unit) {
    val ctx = LocalContext.current
    val add: (String, String) -> Unit = { rawName, text ->
        try {
            Mobile.checkWireGuard(text)
            val name = Store.tunnelName(rawName, settings.tunnels.map { it.name })
            update(settings.copy(tunnels = settings.tunnels + Tunnel(name, text)))
            say("Imported as tunnel:$name. Restart the VPN to use it.")
        } catch (e: Exception) {
            say("Not a usable WireGuard config: ${e.message}")
        }
    }
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        val text = ctx.contentResolver.openInputStream(uri)?.bufferedReader()?.readText() ?: return@rememberLauncherForActivityResult
        var name = "vpn"
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) name = it.getString(0)
        }
        add(name, text)
    }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { add("qr", it) } }
    var confirmDelete by remember { mutableStateOf<Tunnel?>(null) }

    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button({ pickFile.launch(arrayOf("*/*")) }) { Text("Import file") }
            OutlinedButton({
                scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("WireGuard QR code").setBeepEnabled(false))
            }) { Text("Scan QR") }
        }
        settings.tunnels.forEach { t ->
            val sum = remember(t.conf) { runCatching { JSONObject(Mobile.checkWireGuard(t.conf)) }.getOrNull() }
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("tunnel:${t.name}", style = MaterialTheme.typography.titleSmall)
                        sum?.let {
                            Text(
                                "${it.optJSONArray("addresses")?.join(", ")?.replace("\"", "")} → ${it.optJSONArray("endpoints")?.join(", ")?.replace("\"", "")}",
                                style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                    TextButton({ confirmDelete = t }) { Text("Delete") }
                }
            }
        }
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
                        tunnels = settings.tunnels - t,
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

private class AppEntry(val pkg: String, val label: String, val info: ApplicationInfo, val system: Boolean)

@Composable
private fun AppsScreen(settings: Settings, update: (Settings) -> Unit) {
    val ctx = LocalContext.current
    val pm = ctx.packageManager
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.packageName != ctx.packageName && pm.checkPermission(android.Manifest.permission.INTERNET, it.packageName) == PackageManager.PERMISSION_GRANTED }
                .map { AppEntry(it.packageName, pm.getApplicationLabel(it).toString(), it, it.flags and ApplicationInfo.FLAG_SYSTEM != 0 && pm.getLaunchIntentForPackage(it.packageName) == null) }
                .sortedBy { it.label.lowercase() }
        }
    }
    Column(Modifier.padding(horizontal = 16.dp)) {
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("All other apps:", Modifier.weight(1f))
            RoutePicker(settings.defaultRoute, settings.routes()) { update(settings.copy(defaultRoute = it)) }
        }
        OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search apps") }, singleLine = true)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(showSystem, { showSystem = it })
            Text("Show system services")
        }
        LazyColumn {
            items(apps.filter { (showSystem || !it.system) && (query.isBlank() || it.label.contains(query, true) || it.pkg.contains(query, true)) }, key = { it.pkg }) { a ->
                val icon = remember(a.pkg) { runCatching { pm.getApplicationIcon(a.info).toBitmap(96, 96).asImageBitmap() }.getOrNull() }
                val route = settings.apps[a.pkg]
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    icon?.let { Image(it, null, Modifier.size(36.dp)) } ?: Spacer(Modifier.size(36.dp))
                    Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                        Text(a.label, maxLines = 1)
                        Text(a.pkg, style = MaterialTheme.typography.bodySmall, maxLines = 1)
                    }
                    if (settings.filterLists.isNotEmpty()) {
                        val filtered = a.pkg !in settings.unfiltered
                        FilterChip(filtered, {
                            update(settings.copy(unfiltered = if (filtered) settings.unfiltered + a.pkg else settings.unfiltered - a.pkg))
                        }, label = { Text("filter") })
                        Spacer(Modifier.width(6.dp))
                    }
                    RoutePicker(route ?: "default", listOf("default") + settings.routes()) { r ->
                        update(settings.copy(apps = if (r == "default") settings.apps - a.pkg else settings.apps + (a.pkg to r)))
                    }
                }
            }
        }
    }
}

@Composable
private fun RoutePicker(current: String, choices: List<String>, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        AssistChip(onClick = { open = true }, label = { Text(current) })
        DropdownMenu(open, { open = false }) {
            choices.forEach { r ->
                DropdownMenuItem(text = { Text(r) }, onClick = { open = false; onPick(r) })
            }
        }
    }
}
