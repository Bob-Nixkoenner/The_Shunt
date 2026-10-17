package org.theshunt.app

import android.text.format.Formatter
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** The history of the core (Engine.history): traffic and DNS blocks in steps. */
class History(private val o: JSONObject) {
    private val pts = o.getJSONArray("points")
    val size get() = pts.length()
    val step get() = o.optLong("step", 1)
    val rx get() = o.optLong("rx")
    val tx get() = o.optLong("tx")
    val dnsToday get() = o.optLong("dns_today")
    val dnsMonth get() = o.optLong("dns_month")
    fun rx(i: Int) = pts.getJSONObject(i).optLong("rx")
    fun tx(i: Int) = pts.getJSONObject(i).optLong("tx")
    fun dns(i: Int) = pts.getJSONObject(i).optLong("dns")

    /** rx+tx of one tunnel per step, null if it has no history. */
    fun tunnel(name: String): List<Long>? =
        o.optJSONObject("tunnels")?.optJSONArray(name)?.let { a -> List(a.length()) { a.optLong(it) } }
}

val HISTORY_RANGES = listOf("1h", "24h", "7d", "30d")

/** Loads the history of a range every 15 s while shown (the VPN must run). */
@Composable
fun rememberHistory(range: String): State<History?> {
    val running by VpnState.running.collectAsStateWithLifecycle()
    val state = remember { mutableStateOf<History?>(null) }
    LaunchedEffect(running, range) {
        while (running) {
            val h = withContext(Dispatchers.Default) {
                runCatching { VpnState.engine?.history(range)?.let { History(JSONObject(it)) } }.getOrNull()
            }
            if (h != null) state.value = h
            delay(15_000)
        }
        state.value = null
    }
    return state
}

/** Down and up as filled lines, newest on the right. */
@Composable
fun TrafficChart(h: History, modifier: Modifier = Modifier) {
    val c = LocalShunt.current
    Canvas(modifier.fillMaxWidth().height(110.dp)) {
        val n = h.size
        if (n < 2) return@Canvas
        val max = maxOf(1L, (0 until n).maxOf { maxOf(h.rx(it), h.tx(it)) }).toFloat()
        fun line(v: (Int) -> Long, close: Boolean): Path = Path().apply {
            for (i in 0 until n) {
                val x = size.width * i / (n - 1)
                val y = size.height - size.height * v(i) / max
                if (i == 0) moveTo(x, y) else lineTo(x, y)
            }
            if (close) { lineTo(size.width, size.height); lineTo(0f, size.height); close() }
        }
        for (f in listOf(0.25f, 0.5f, 0.75f)) drawLine(c.line, Offset(0f, size.height * f), Offset(size.width, size.height * f), 1f)
        drawPath(line(h::tx, true), c.info.copy(alpha = 0.25f))
        drawPath(line(h::rx, true), c.accent.copy(alpha = 0.30f))
        drawPath(line(h::tx, false), c.info, style = Stroke(3f))
        drawPath(line(h::rx, false), c.accent, style = Stroke(3f))
    }
}

/** Bars of names blocked by the DNS filter. */
@Composable
fun BlocksChart(h: History, modifier: Modifier = Modifier) {
    val c = LocalShunt.current
    Canvas(modifier.fillMaxWidth().height(44.dp)) {
        val n = h.size
        if (n == 0) return@Canvas
        val max = maxOf(1L, (0 until n).maxOf { h.dns(it) }).toFloat()
        val bw = size.width / n
        for (i in 0 until n) {
            val v = h.dns(i)
            if (v == 0L) continue
            val bh = size.height * v / max
            drawRect(c.warn, Offset(i * bw + bw * 0.12f, size.height - bh), androidx.compose.ui.geometry.Size(bw * 0.76f, bh))
        }
    }
}

/** A small history line for a tunnel card. */
@Composable
fun Sparkline(values: List<Long>?, modifier: Modifier = Modifier) {
    val c = LocalShunt.current
    if (values == null || values.size < 2) return
    Canvas(modifier.fillMaxWidth().height(24.dp)) {
        val max = maxOf(1L, values.max()).toFloat()
        val p = Path()
        values.forEachIndexed { i, v ->
            val x = size.width * i / (values.size - 1)
            val y = size.height - size.height * v / max
            if (i == 0) p.moveTo(x, y) else p.lineTo(x, y)
        }
        val fill = Path().apply { addPath(p); lineTo(size.width, size.height); lineTo(0f, size.height); close() }
        drawPath(fill, c.accent.copy(alpha = 0.22f))
        drawPath(p, c.accent, style = Stroke(2f))
    }
}

@Composable
private fun Kpi(value: String, label: String, color: Color, modifier: Modifier) {
    val c = LocalShunt.current
    Column(modifier) {
        Text(value, fontWeight = FontWeight.Bold, fontSize = 17.sp, color = c.text)
        Text(label, fontSize = 11.sp, color = color)
    }
}

/** "Traffic and blocks": graph, DNS blocks today and this month, range switch. */
@Composable
fun HistorySection(h: History?, range: String, onRange: (String) -> Unit) {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    Section("Traffic and blocks") {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            for (r in HISTORY_RANGES) ShuntButton(r, { onRange(r) }, kind = if (r == range) Tone.Ok else Tone.Neutral, modifier = Modifier.weight(1f))
        }
        Spacer(Modifier.height(8.dp))
        if (h == null) { Hint("Loading…"); return@Section }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
            Kpi("↓ " + Formatter.formatShortFileSize(ctx, h.rx), "downloaded", c.accent, Modifier.weight(1f))
            Kpi("↑ " + Formatter.formatShortFileSize(ctx, h.tx), "uploaded", c.info, Modifier.weight(1f))
            Kpi(h.dnsToday.toString(), "blocked today", c.warn, Modifier.weight(1f))
            Kpi(h.dnsMonth.toString(), "this month", c.warn, Modifier.weight(1f))
        }
        Spacer(Modifier.height(8.dp))
        TrafficChart(h)
        Spacer(Modifier.height(4.dp))
        BlocksChart(h)
        Hint("Through your tunnels only; direct traffic is not measured. Counted on this phone, nothing is sent anywhere.")
    }
}
