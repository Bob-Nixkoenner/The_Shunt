package org.theshunt.app

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.random.Random

/**
 * Disguise on foreign Wi-Fi: the device name others see (DHCP, hotspot,
 * nearby devices) can be replaced by a random common one. Android lets an
 * app change it only with WRITE_SECURE_SETTINGS, which is granted once from
 * a computer (adb). The MAC address cannot be set by an app at all; the
 * section links to the system settings that randomize it.
 */
object Disguise {
    private const val PREFS = "disguise"
    private const val KEY_ORIGINAL = "original_name"
    private const val KEY_AUTO = "roll_on_wifi"
    const val GRANT = "adb shell pm grant org.theshunt.app android.permission.WRITE_SECURE_SETTINGS"

    // common names, so the device blends in instead of standing out
    private val NAMES = listOf(
        "Galaxy A15", "Galaxy A25", "Galaxy A55", "Galaxy S23", "Redmi Note 13", "Redmi 13C",
        "moto g54", "moto g84", "Pixel 7a", "Pixel 8", "OPPO A78", "realme C55", "Nokia G22", "HONOR X8",
    )

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun canWrite(ctx: Context) =
        ctx.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS) == PackageManager.PERMISSION_GRANTED

    fun name(ctx: Context): String = Settings.Global.getString(ctx.contentResolver, "device_name") ?: Build.MODEL

    fun original(ctx: Context): String? = prefs(ctx).getString(KEY_ORIGINAL, null)

    var Context.autoRoll: Boolean
        get() = prefs(this).getBoolean(KEY_AUTO, false)
        set(v) { prefs(this).edit().putBoolean(KEY_AUTO, v).apply() }

    /** Sets a new random name (keeps the real one for restore). Returns it, or null without permission. */
    fun roll(ctx: Context): String? {
        if (!canWrite(ctx)) return null
        val p = prefs(ctx)
        if (p.getString(KEY_ORIGINAL, null) == null) p.edit().putString(KEY_ORIGINAL, name(ctx)).apply()
        val cur = name(ctx)
        var n: String
        do { n = NAMES[Random.nextInt(NAMES.size)] } while (n == cur)
        return try {
            Settings.Global.putString(ctx.contentResolver, "device_name", n); n
        } catch (e: SecurityException) {
            null
        }
    }

    fun restore(ctx: Context): Boolean {
        val o = original(ctx) ?: return false
        return try {
            Settings.Global.putString(ctx.contentResolver, "device_name", o)
            prefs(ctx).edit().remove(KEY_ORIGINAL).apply()
            true
        } catch (e: SecurityException) {
            false
        }
    }

    /** VPN service: a Wi-Fi was left, so the next one sees a fresh name (the name goes out while connecting). */
    fun wifiLost(ctx: Context) {
        if (ctx.autoRoll) roll(ctx)?.let { android.util.Log.i("Shunt", "disguise: device name now $it") }
    }
}

@Composable
fun DisguiseSection() {
    val ctx = LocalContext.current
    val c = LocalShunt.current
    var name by remember { mutableStateOf(Disguise.name(ctx)) }
    var original by remember { mutableStateOf(Disguise.original(ctx)) }
    val can = remember { Disguise.canWrite(ctx) }
    var auto by remember { mutableStateOf(with(Disguise) { ctx.autoRoll }) }
    fun open(action: String) = try {
        ctx.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (e: Exception) {
        ctx.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    Section("Disguise on foreign Wi-Fi") {
        EdgeCard(if (original != null) Tone.Ok else Tone.Neutral) {
            KV("device name", name, mono = true)
            original?.let { KV("real name", it, mono = true) }
            if (can) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ShuntButton("Random name", { Disguise.roll(ctx)?.let { name = it; original = Disguise.original(ctx) } }, kind = Tone.Ok)
                    if (original != null) ShuntButton("Restore", { if (Disguise.restore(ctx)) { name = Disguise.name(ctx); original = null } })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("New name after every Wi-Fi", color = c.text, fontSize = 14.sp)
                        Text("When a Wi-Fi is left, so the next one sees a fresh name.", color = c.muted, fontSize = 12.sp)
                    }
                    Switch(auto, { auto = it; with(Disguise) { ctx.autoRoll = it } })
                }
            } else {
                Hint("To change the name, grant once from a computer (USB debugging):")
                Text(Disguise.GRANT, fontFamily = Mono, fontSize = 11.sp, color = c.text)
            }
        }
        EdgeCard(Tone.Info) {
            Text("MAC address", color = c.text, fontSize = 14.sp)
            Hint(
                "Apps cannot change it; Android can. Per Wi-Fi: Privacy → \"Use randomized MAC\" and, if shown, " +
                    "\"Send device name\" off. For a new MAC on every connection: Developer options → " +
                    "\"Wi-Fi non-persistent MAC randomization\". A new MAC means a new captive-portal login."
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ShuntButton("Wi-Fi settings", { open(Settings.ACTION_WIFI_SETTINGS) })
                ShuntButton("Developer options", { open(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS) })
            }
        }
    }
}
