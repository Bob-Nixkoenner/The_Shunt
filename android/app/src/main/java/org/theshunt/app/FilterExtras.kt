@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package org.theshunt.app

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.theshunt.mobile.Mobile

/** "https://www.Example.com/path" or "example.com." to "example.com"; null when it is no DNS name. */
fun allowName(raw: String): String? {
    var s = raw.trim().lowercase().removePrefix("https://").removePrefix("http://").removePrefix("||")
    s = s.substringBefore('/').substringBefore('^').substringBefore('?').trimEnd('.')
    if (s.startsWith("www.")) s = s.removePrefix("www.")
    return s.takeIf { Regex("^[a-z0-9_-]+(\\.[a-z0-9_-]+)+$").matches(it) }
}

/** The allowlist text with one more name ("||name^": the name and its subdomains); unchanged when it is in already. */
fun withAllowed(text: String, name: String): String {
    val line = "||$name^"
    if (text.lines().any { it.trim().removePrefix("@@") == line }) return text
    return (if (text.isEmpty() || text.endsWith("\n")) text else text + "\n") + line + "\n"
}

/**
 * The Pro parts of the Filter tab: own lists by address, the last blocked names (each can be
 * allowed with one tap) and the names that are never blocked.
 */
@Composable
fun FilterExtras(settings: Settings, update: (Settings) -> Unit, status: JSONObject?, say: (String) -> Unit) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var label by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var site by remember { mutableStateOf("") }
    var customs by remember { mutableStateOf(Blocklists.customLists(ctx)) }
    var counts by remember { mutableStateOf<Map<String, Int>>(emptyMap()) }
    var editText by remember(settings.allowText) { mutableStateOf(settings.allowText) }

    LaunchedEffect(customs, settings.filterLists) {
        counts = withContext(Dispatchers.IO) { customs.associate { it.name to Blocklists.count(ctx, it.name) } }
    }

    if (settings.shows("filter.custom")) Section("Own lists") {
        Hint("Add a filter list by its web address. Format: a text file with one entry per line. Understood: example.com (exactly this name), 0.0.0.0 example.com (hosts file) and ||example.com^ (this name and all its subdomains, as in AdGuard or uBlock lists). Lines that start with # or ! are comments; everything else (wildcards, paths, rules with options) is skipped. The address must start with https://.")
        customs.forEach { l ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.beside)) {
                Box(Modifier.weight(1f)) {
                    CheckRow(l.name in settings.filterLists, { on ->
                        update(settings.copy(filterLists = if (on) settings.filterLists + l.name else settings.filterLists - l.name))
                    }) {
                        Column(Modifier.weight(1f)) {
                            Text(l.name, color = c.text, fontWeight = FontWeight.SemiBold)
                            Text(l.url.removePrefix("https://").take(60), color = c.muted, fontSize = 12.sp, fontFamily = Mono, maxLines = 1)
                            counts[l.name]?.takeIf { it > 0 }?.let { Text(if (it == 1) T("1 name") else T("{n} names", "n" to "%,d".format(it)), color = c.muted, fontSize = 12.sp) }
                        }
                    }
                }
                ShuntLink("Remove", {
                    Blocklists.removeCustom(ctx, l.name)
                    customs = Blocklists.customLists(ctx)
                    update(settings.copy(filterLists = settings.filterLists - l.name))
                }, color = c.bad)
            }
        }
        OutlinedTextField(label, { label = it.take(24) }, label = { Text(T("name (optional)")) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(address, { address = it.trim() }, label = { Text(T("address of the list (https://…)")) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        ShuntButton("Add list", {
            val l = label
            val a = address
            busy = true
            scope.launch {
                val r = withContext(Dispatchers.IO) { runCatching { Blocklists.addCustom(ctx, l, a) } }
                busy = false
                r.onSuccess { name ->
                    customs = Blocklists.customLists(ctx)
                    label = ""
                    address = ""
                    update(settings.copy(filterLists = settings.filterLists + name))
                    say(T("List {name} added and switched on.", "name" to name))
                }.onFailure { say(it.message ?: it.javaClass.simpleName) }
            }
        }, kind = Tone.Ok, enabled = !busy && address.isNotBlank())
        if (busy) Text(T("Working …"), color = c.muted, fontSize = 13.sp)
    }

    if (settings.shows("filter.recent")) Section("Recently blocked") {
        val recent = status?.optJSONArray("dns_recent")
        val n = minOf(recent?.length() ?: 0, 10)
        if (n == 0) Hint("Nothing blocked since the VPN started.")
        for (i in 0 until n) {
            val q = recent!!.getJSONObject(i)
            val name = q.optString("name")
            val time = runCatching { java.time.OffsetDateTime.parse(q.optString("time")).toLocalTime().withNano(0).toString() }.getOrDefault("")
            val allowed = allowName(name)?.let { a -> settings.allowText.lines().any { it.trim().removePrefix("@@") == "||$a^" } } == true
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Gap.beside)) {
                Column(Modifier.weight(1f)) {
                    Text(name, fontFamily = Mono, fontSize = 13.sp, color = c.text, maxLines = 1)
                    Text(listOf(time, q.optString("list")).filter { it.isNotEmpty() }.joinToString(" · "), color = c.muted, fontSize = 11.sp, maxLines = 1)
                }
                if (settings.shows("filter.allow")) {
                    if (allowed) Text(T("allowed"), color = c.ok, fontSize = 12.sp)
                    else ShuntLink("Allow", { allowName(name)?.let { a -> update(settings.copy(allowText = withAllowed(settings.allowText, a))); say(T("{name} is allowed from now on.", "name" to a)) } })
                }
            }
        }
    }

    if (settings.shows("filter.allow")) Section("Never block") {
        Hint("Names here are never blocked, for every app, with all their subdomains. Add one site below, or paste a whole list. Format: one entry per line: example.com, ||example.com^ or @@||example.com^ (AdGuard exception). Lines that start with # or ! are comments. A plain name or a hosts line allows exactly that name; ||name^ allows its subdomains too.")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(site, { site = it }, label = { Text(T("site, e.g. example.com")) }, singleLine = true, modifier = Modifier.weight(1f))
            ShuntButton("Allow", {
                val a = allowName(site)
                if (a == null) say(T("That is not a site name like example.com"))
                else { update(settings.copy(allowText = withAllowed(settings.allowText, a))); site = ""; say(T("{name} is allowed from now on.", "name" to a)) }
            }, kind = Tone.Ok, enabled = site.isNotBlank())
        }
        OutlinedTextField(editText, { editText = it }, label = { Text(T("allowed names, one per line")) }, minLines = 4, maxLines = 12, modifier = Modifier.fillMaxWidth())
        val summary = remember(editText) {
            if (editText.isBlank()) "" else runCatching { JSONObject(Mobile.checkFilterText(editText, true)).optInt("names").toString() }.getOrNull()
        }
        if (summary == null) Hint("No usable entry found: check the format above.")
        else if (summary.isNotEmpty()) Hint(T("{n} names will be allowed.", "n" to summary))
        ShuntButton("Save", { update(settings.copy(allowText = editText.trim().let { if (it.isEmpty()) "" else it + "\n" })); say(T("Saved.")) },
            kind = Tone.Ok, enabled = editText != settings.allowText && (editText.isBlank() || summary != null))
    }
}
