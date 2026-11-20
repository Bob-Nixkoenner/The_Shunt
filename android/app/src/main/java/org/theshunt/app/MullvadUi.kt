@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package org.theshunt.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A drop-down list of (value, text) pairs. */
@Composable
private fun Pick(value: String, options: List<Pair<String, String>>, onPick: (String) -> Unit, modifier: Modifier = Modifier) {
    var open by remember { mutableStateOf(false) }
    val c = LocalShunt.current
    Box(modifier) {
        Row(Modifier.clickable { open = true }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(options.firstOrNull { it.first == value }?.second ?: value, color = c.text, fontSize = 14.sp, maxLines = 1)
            Text(" ▾", color = c.muted, fontSize = 12.sp)
        }
        DropdownMenu(open, { open = false }, containerColor = c.panel2) {
            options.forEach { (v, label) -> DropdownMenuItem(text = { Text(label) }, onClick = { open = false; onPick(v) }) }
        }
    }
}

/**
 * Mullvad on the Tunnels tab: log in (one or more accounts), pick a country, city or server
 * for a tunnel, build a chain of tunnels, delete it again. See Mullvad.kt.
 */
@Composable
fun MullvadSection(settings: Settings, update: (Settings) -> Unit, say: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var countries by remember { mutableStateOf<List<MullvadCountry>>(emptyList()) }
    var loadError by remember { mutableStateOf("") }
    var loginName by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var tunnel by remember { mutableStateOf("mullvad") }
    var useLogin by remember { mutableStateOf("") }
    var country by remember { mutableStateOf("") }
    var city by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("") }
    var via by remember { mutableStateOf("") }
    var chainName by remember { mutableStateOf("chain") }
    var hops by remember { mutableStateOf("3") }
    var entry by remember { mutableStateOf("") }
    var exitCc by remember { mutableStateOf("") }
    var confirmLogout by remember { mutableStateOf<MullvadLogin?>(null) }
    var confirmChain by remember { mutableStateOf<String?>(null) }
    val c = LocalShunt.current
    val loggedIn = settings.mullvadLogins.isNotEmpty()

    // the server list once a login exists (and again after a failed try, by the "reload" link)
    var reload by remember { mutableStateOf(0) }
    LaunchedEffect(loggedIn, reload) {
        if (!loggedIn || countries.isNotEmpty()) return@LaunchedEffect
        loadError = ""
        try {
            countries = withContext(Dispatchers.IO) { Mullvad.countries() }
        } catch (e: Exception) {
            loadError = e.message ?: e.javaClass.simpleName
        }
    }

    /** Runs a Mullvad operation off the main thread; the result becomes the settings. */
    fun run(done: String, op: () -> Settings) {
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching(op) }
            busy = false
            r.onSuccess { update(it); say(done) }.onFailure { say(it.message ?: it.javaClass.simpleName) }
        }
    }

    val carriers = settings.tunnels.filter { !it.isOpenVPN && !it.isTor }.map { "tunnel:${it.name}" }
    val loginOptions = settings.mullvadLogins.map { it.name to it.name }
    val chains = settings.mullvadExits.filter { it.chain.isNotEmpty() && settings.tunnels.any { t -> t.name == it.tunnel } }
        .groupBy { it.chain }
    val singles = settings.mullvadExits.filter { it.chain.isEmpty() && settings.tunnels.any { t -> t.name == it.tunnel } }

    Section("Mullvad") {
        Hint("Your account number stays on this phone, sealed with its key store. The tunnel is a normal WireGuard tunnel; Shunt registers its own key as a device of your account (Mullvad allows 5) and removes it again when you log out.")
        settings.mullvadLogins.forEach { l ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(l.name, fontWeight = FontWeight.Bold, color = c.text, fontSize = 14.sp)
                Text(T("Account {account}, device {device}", "account" to l.masked, "device" to l.deviceName), color = c.muted, fontSize = 12.sp, modifier = Modifier.weight(1f))
                ShuntLink("Log out", { confirmLogout = l }, color = c.bad, enabled = !busy)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(loginName, { loginName = it.lowercase().take(10) }, label = { Text(T("name (optional)")) }, singleLine = true, modifier = Modifier.weight(0.8f))
            OutlinedTextField(account, { account = it.take(24) }, label = { Text(T("Mullvad account number (16 digits)")) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.weight(1.4f))
        }
        ShuntButton("Log in", {
            val n = loginName
            val a = account
            run(T("Logged in to Mullvad")) { Mullvad.login(settings, n, a) }
            account = ""
            loginName = ""
        }, kind = Tone.Ok, enabled = !busy && account.isNotBlank())
        if (!loggedIn) return@Section

        if (loadError.isNotEmpty()) {
            Hint(T("Could not load the server list: {error}", "error" to loadError))
            ShuntLink("Try again", { reload++ })
        }
        // --- one tunnel on one exit
        Text(T("Tunnel on an exit"), fontWeight = FontWeight.SemiBold, color = c.text, fontSize = 14.sp)
        OutlinedTextField(tunnel, { tunnel = it.lowercase().take(10) }, label = { Text(T("tunnel name")) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (settings.mullvadLogins.size > 1) Pick(useLogin, listOf("" to T("account: …")) + loginOptions, { useLogin = it })
            Pick(country, listOf("" to T("any country")) + countries.map { it.code to "${it.name}" }, { country = it; city = ""; server = "" })
            val cs = countries.firstOrNull { it.code == country }?.cities.orEmpty()
            Pick(city, listOf("" to T("any city")) + cs.map { it.code to "${it.name} (${it.hosts.size})" }, { city = it; server = "" })
            val hs = cs.firstOrNull { it.code == city }?.hosts.orEmpty()
            Pick(server, listOf("" to T("any server")) + hs.map { it to it }, { server = it })
        }
        // like the desktop window (index.html #mv-via): not tied to the level, the whole
        // Mullvad module is for people who want this; it needs a WireGuard tunnel to go through
        if (carriers.isNotEmpty()) Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(T("connects"), color = c.muted, fontSize = 13.sp)
            Pick(via, listOf("" to T("directly to the server")) + carriers.map { it to T("through {name} (multi-hop)", "name" to it.removePrefix("tunnel:")) }, { via = it })
        }
        ShuntButton("Use this exit", {
            run(T("Tunnel {name} is on its new Mullvad exit. Restart the VPN to use it.", "name" to tunnel)) {
                Mullvad.connect(settings, tunnel, useLogin, MullvadChoice(country, city, server), via)
            }
        }, kind = Tone.Ok, enabled = !busy && tunnel.isNotBlank())
        singles.forEach { x ->
            KV(x.tunnel, x.country + ", " + x.city + " · " + x.hostname + (if (settings.mullvadLogins.size > 1) " · " + x.account else ""), mono = true)
        }

        // --- chain builder
        Text(T("Chain builder"), fontWeight = FontWeight.SemiBold, color = c.text, fontSize = 14.sp)
        OutlinedTextField(chainName, { chainName = it.lowercase().take(8) }, label = { Text(T("chain name")) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Pick(hops, listOf("2" to T("2 hops"), "3" to T("3 hops"), "4" to T("4 hops")), { hops = it })
            Pick(entry, listOf("" to T("entry: any country")) + countries.map { it.code to it.name }, { entry = it })
            Pick(exitCc, listOf("" to T("exit: any country")) + countries.map { it.code to it.name }, { exitCc = it })
        }
        Hint("Every hop gets another country and, where possible, another hosting provider. The tunnels are named NAME1 (entry) … NAMEn (exit): use the last one in your rules. Each hop costs speed (about 100 ms and a share of the bandwidth).")
        if (settings.mullvadLogins.size == 1) Hint("Only one account is logged in, so every hop uses the same Mullvad key and Mullvad can link the hops. Log in a second account (name it above) to give each hop its own.")
        ShuntButton("Build chain", {
            run(T("Chain {name} is ready: use {last} in your rules. Restart the VPN to use it.", "name" to chainName, "last" to chainName + hops)) {
                Mullvad.chain(settings, chainName, hops.toInt(), entry, exitCc, emptyList(), via)
            }
        }, kind = Tone.Ok, enabled = !busy && chainName.isNotBlank())
        chains.forEach { (name, list) ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Column(Modifier.weight(1f)) {
                    Text(T("Chain {name}", "name" to name), fontWeight = FontWeight.Bold, color = c.text, fontSize = 14.sp)
                    list.sortedBy { it.tunnel }.forEach { x ->
                        Text("${x.tunnel}: ${x.country}, ${x.city}" + if (x.provider.isNotEmpty()) " · ${x.provider}" else "", color = c.muted, fontSize = 12.sp)
                    }
                }
                ShuntLink("Delete chain", { confirmChain = name }, color = c.bad, enabled = !busy)
            }
        }
        if (busy) Text(T("Working …"), color = c.muted, fontSize = 13.sp)
    }

    confirmLogout?.let { l ->
        AlertDialog(
            onDismissRequest = { confirmLogout = null },
            title = { Text(T("Log out of Mullvad?")) },
            text = { Text(T("The Mullvad tunnels of the account {name} are removed and the device is deleted at Mullvad.", "name" to l.name)) },
            confirmButton = {
                TextButton({
                    confirmLogout = null
                    run(T("Logged out of Mullvad")) { Mullvad.logout(settings, l.name) }
                }) { Text(T("Log out")) }
            },
            dismissButton = { TextButton({ confirmLogout = null }) { Text(T("Cancel")) } },
        )
    }
    confirmChain?.let { name ->
        AlertDialog(
            onDismissRequest = { confirmChain = null },
            title = { Text(T("Delete chain {name}? All its hops are removed.", "name" to name)) },
            text = { Text(T("Apps routed to it are blocked until you pick another route.")) },
            confirmButton = {
                TextButton({
                    confirmChain = null
                    run(T("Chain {name} deleted", "name" to name)) { Mullvad.deleteChain(settings, name) }
                }) { Text(T("Delete chain")) }
            },
            dismissButton = { TextButton({ confirmChain = null }) { Text(T("Cancel")) } },
        )
    }
}
