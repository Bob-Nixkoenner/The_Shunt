package org.theshunt.app

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The colours of the desktop web UI (internal/ui/static/index.html, :root),
 * so the app and the desktop look like one product. [ok] is the status green
 * ("up", "protected"): it stays green in every level, while [accent] turns
 * violet in Opsec.
 */
@Immutable
data class ShuntColors(
    val bg: Color, val panel: Color, val panel2: Color, val line: Color,
    val text: Color, val muted: Color, val accent: Color, val accentInk: Color,
    val ok: Color = accent,
    val warn: Color = Color(0xFFF5B942), val bad: Color = Color(0xFFF2555A), val info: Color = Color(0xFF6AA8FF),
)

val DarkShunt = ShuntColors(
    bg = Color(0xFF0D1117), panel = Color(0xFF151B23), panel2 = Color(0xFF1B2330), line = Color(0xFF263040),
    text = Color(0xFFE6EDF3), muted = Color(0xFF8B98A8), accent = Color(0xFF34D399), accentInk = Color(0xFF052E1F),
)
val LightShunt = ShuntColors(
    bg = Color(0xFFF5F7FA), panel = Color(0xFFFFFFFF), panel2 = Color(0xFFEEF2F6), line = Color(0xFFD8DEE6),
    text = Color(0xFF17202B), muted = Color(0xFF5D6B7B), accent = Color(0xFF059669), accentInk = Color(0xFFFFFFFF),
    // darker than the dark theme's: yellow text on a pale yellow pill was hard to read
    warn = Color(0xFFA15C07), bad = Color(0xFFC9262C), info = Color(0xFF2563EB),
)

/**
 * Opsec: violet accent, the same tokens as the desktop (text contrast at least
 * 4.5:1 on every background). Status colours (ok, bad, warn) stay as they are.
 */
val DarkOpsec = DarkShunt.copy(accent = Color(0xFFB794F6), accentInk = Color(0xFF1E0B3A))
val LightOpsec = LightShunt.copy(accent = Color(0xFF6D28D9), accentInk = Color(0xFFFFFFFF))

val LocalShunt = staticCompositionLocalOf { DarkShunt }

/** Light/dark: follow the phone (default) or fixed. Kept apart from the VPN settings. */
enum class ThemeMode(val label: String) { System("System"), Light("Light"), Dark("Dark") }

object UiPrefs {
    private const val PREFS = "ui"
    private const val KEY = "theme"
    var mode by mutableStateOf(ThemeMode.System)
        private set

    fun load(ctx: Context) {
        mode = ThemeMode.entries.firstOrNull { it.name == ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null) } ?: ThemeMode.System
    }

    fun set(ctx: Context, m: ThemeMode) {
        mode = m
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, m.name).apply()
    }

    @Composable
    fun dark(): Boolean = when (mode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
    }
}

/** "Appearance": a card with the three choices. */
@Composable
fun AppearanceSection() {
    val ctx = LocalContext.current
    Section("Appearance") {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            for (m in ThemeMode.entries) ShuntButton(T(m.label), { UiPrefs.set(ctx, m) }, kind = if (UiPrefs.mode == m) Tone.Ok else Tone.Neutral, modifier = Modifier.weight(1f))
        }
        Hint("System follows the phone's dark mode.")
    }
}
val Mono = FontFamily.Monospace

@Composable
fun ShuntTheme(dark: Boolean, opsec: Boolean = false, content: @Composable () -> Unit) {
    val c = when {
        opsec -> if (dark) DarkOpsec else LightOpsec
        else -> if (dark) DarkShunt else LightShunt
    }
    val base = if (dark) darkColorScheme() else lightColorScheme()
    val scheme = base.copy(
        primary = c.accent, onPrimary = c.accentInk,
        secondary = c.info, onSecondary = c.bg,
        background = c.bg, onBackground = c.text,
        surface = c.panel, onSurface = c.text,
        surfaceVariant = c.panel2, onSurfaceVariant = c.muted,
        surfaceContainer = c.panel, surfaceContainerHigh = c.panel2, surfaceContainerHighest = c.panel2,
        surfaceContainerLow = c.panel, surfaceContainerLowest = c.bg,
        outline = c.line, outlineVariant = c.line,
        error = c.bad, onError = Color.White, errorContainer = c.bad.copy(alpha = .16f), onErrorContainer = c.text,
        secondaryContainer = c.panel2, onSecondaryContainer = c.text,
    )
    // status and navigation bar icons must match the theme, also when it differs from the phone's
    val view = LocalView.current
    if (!view.isInEditMode) SideEffect {
        var ctx = view.context
        while (ctx is ContextWrapper && ctx !is Activity) ctx = ctx.baseContext
        (ctx as? Activity)?.window?.let { w ->
            WindowCompat.getInsetsController(w, view).apply { isAppearanceLightStatusBars = !dark; isAppearanceLightNavigationBars = !dark }
        }
    }
    CompositionLocalProvider(LocalShunt provides c) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/** The track-switch logo of the web UI header. */
@Composable
fun ShuntLogo(size: Int = 26) {
    val accent = LocalShunt.current.accent
    Canvas(Modifier.size(size.dp)) {
        val s = this.size.width / 32f
        val p = Path().apply {
            moveTo(3 * s, 24 * s); lineTo(11 * s, 24 * s); lineTo(21 * s, 8 * s); lineTo(29 * s, 8 * s)
            moveTo(11 * s, 24 * s); lineTo(29 * s, 24 * s)
        }
        drawPath(p, accent, style = Stroke(width = 3 * s, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

/** A panel with an uppercase heading, like the web UI's <section><h2>. */
@Composable
fun Section(title: String, modifier: Modifier = Modifier, action: (@Composable () -> Unit)? = null, content: @Composable ColumnScope.() -> Unit) {
    val c = LocalShunt.current
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(c.panel)
            .border(1.dp, c.line, RoundedCornerShape(10.dp)).padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                T(title).uppercase(), Modifier.weight(1f), color = c.muted,
                style = TextStyle(fontSize = 13.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.sp),
            )
            action?.invoke()
        }
        content()
    }
}

enum class Tone { Neutral, Ok, Bad, Warn, Info }

@Composable
private fun toneColor(t: Tone): Color {
    val c = LocalShunt.current
    return when (t) {
        Tone.Ok -> c.ok; Tone.Bad -> c.bad; Tone.Warn -> c.warn; Tone.Info -> c.info; Tone.Neutral -> c.muted
    }
}

/** Rounded status label (web: .pill.ok/.bad/.warn). */
@Composable
fun Pill(text: String, tone: Tone = Tone.Neutral) {
    val c = LocalShunt.current
    val fg = toneColor(tone)
    val bg = if (tone == Tone.Neutral) c.panel2 else fg.copy(alpha = .18f)
    Text(
        T(text), Modifier.clip(RoundedCornerShape(50)).background(bg).padding(horizontal = 10.dp, vertical = 3.dp),
        color = fg, style = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
    )
}

fun routeTone(route: String): Tone = when {
    route == "direct" -> Tone.Info
    route == "block" -> Tone.Bad
    route.startsWith("tunnel:") -> Tone.Ok
    route.startsWith("link:") -> Tone.Warn
    else -> Tone.Neutral
}

/** A route name in its colour (web: .route.direct/.block/.tunnel). */
@Composable
fun RouteTag(route: String, modifier: Modifier = Modifier) {
    val c = LocalShunt.current
    Text(
        T(route), modifier.clip(RoundedCornerShape(6.dp)).background(c.panel2).padding(horizontal = 7.dp, vertical = 2.dp),
        color = if (route == "default") c.muted else toneColor(routeTone(route)),
        style = TextStyle(fontFamily = Mono, fontSize = 12.5.sp),
        maxLines = 1,
    )
}

/** Card with a coloured left edge (web: .card.up/.down, .leakrow.ok/…). */
@Composable
fun EdgeCard(tone: Tone, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val c = LocalShunt.current
    val edge = if (tone == Tone.Neutral) c.muted else toneColor(tone)
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(9.dp)).background(c.panel2)
            .drawBehind { drawRect(edge, Offset.Zero, androidx.compose.ui.geometry.Size(3.dp.toPx(), size.height)) }
            .padding(start = 15.dp, end = 12.dp, top = 12.dp, bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = content,
    )
}

/** Muted key, value beside it (web: .kv). */
@Composable
fun KV(key: String, value: String, mono: Boolean = false, valueColor: Color? = null) {
    val c = LocalShunt.current
    Row {
        Text(T(key), Modifier.width(92.dp), color = c.muted, style = TextStyle(fontSize = 13.sp))
        Text(
            value, color = valueColor ?: c.text,
            style = if (mono) TextStyle(fontFamily = Mono, fontSize = 12.5.sp) else TextStyle(fontSize = 13.sp),
        )
    }
}

/** Warning strip above the sections (web: .banner / .banner.bad). */
@Composable
fun Banner(title: String, text: String, bad: Boolean = false, action: (@Composable () -> Unit)? = null) {
    val c = LocalShunt.current
    val col = if (bad) c.bad else c.warn
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(col.copy(alpha = .14f))
            .border(BorderStroke(1.dp, col.copy(alpha = .5f)), RoundedCornerShape(10.dp)).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(T(title), fontWeight = FontWeight.Bold, color = c.text)
        Text(T(text), color = c.text, style = TextStyle(fontSize = 13.sp))
        action?.invoke()
    }
}

@Composable
fun Hint(text: String) {
    Text(T(text), color = LocalShunt.current.muted, style = TextStyle(fontSize = 12.5.sp))
}

/** Buttons of the web UI: plain, primary (accent) and danger (red). */
@Composable
fun ShuntButton(text: String, onClick: () -> Unit, kind: Tone = Tone.Neutral, enabled: Boolean = true, modifier: Modifier = Modifier) {
    val c = LocalShunt.current
    val (bg, fg) = when (kind) {
        Tone.Ok -> c.accent to c.accentInk
        Tone.Bad -> c.bad to Color.White
        else -> c.panel2 to c.text
    }
    Button(
        onClick, modifier, enabled = enabled, shape = RoundedCornerShape(8.dp),
        colors = ButtonDefaults.buttonColors(containerColor = bg, contentColor = fg),
        border = if (kind == Tone.Neutral) BorderStroke(1.dp, c.line) else null,
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
    ) { Text(T(text), fontWeight = if (kind == Tone.Neutral) FontWeight.Normal else FontWeight.Bold) }
}
