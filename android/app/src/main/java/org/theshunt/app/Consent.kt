package org.theshunt.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

const val PRIVACY_URL = "https://bob-nixkoenner.github.io/The_Shunt/privacy.html"

/** Whether the person accepted the VPN data disclosure (Google Play: prominent disclosure and consent). */
object Consent {
    private const val PREFS = "consent"
    private const val KEY = "vpn_disclosure_v1"

    fun given(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, false)

    fun accept(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, true).apply()
    }
}

/** First start: say what the VPN service sees and ask. Nothing runs before "Accept". */
@Composable
fun ConsentGate(onDecline: () -> Unit, content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    var ok by remember { mutableStateOf(Consent.given(ctx)) }
    if (ok) { content(); return }
    val c = LocalShunt.current
    Column(Modifier.fillMaxSize().systemBarsPadding().padding(20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(T("Before you start"), fontWeight = FontWeight.Bold, fontSize = 22.sp, color = c.text)
            Text(T("The Shunt uses Android's VPN service. Through it the app handles the network traffic of the apps you choose, to send it through the tunnels you set up."), color = c.text)
            Text(T("What the app can see"), fontWeight = FontWeight.Bold, color = c.text)
            Text(
                listOf(
                    T("• The list of apps installed on this phone, to let you pick which app uses which tunnel."),
                    T("• The network connections of those apps: destination addresses, ports and DNS names, to apply your rules and the DNS filter."),
                    T("• Your tunnel keys and settings."),
                ).joinToString("\n"),
                color = c.text,
            )
            Text(T("What happens with it"), fontWeight = FontWeight.Bold, color = c.text)
            Text(
                listOf(
                    T("• All of this is processed on this phone only. The developer receives nothing: no account, no analytics, no advertising."),
                    T("• Traffic is sent, encrypted by the tunnel, to the server you entered. Its operator then handles it under their own policy."),
                    T("• The app itself contacts GitHub (DNS filter lists, only if you switch them on) and api.ipify.org (only when you start the leak test)."),
                    T("• Nothing is sold or shared."),
                ).joinToString("\n"),
                color = c.text,
            )
            ShuntLink("Read the privacy policy", { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PRIVACY_URL))) })
        }
        Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ShuntButton("Decline", onDecline, modifier = Modifier.weight(1f))
            ShuntButton("Accept", { Consent.accept(ctx); ok = true }, kind = Tone.Ok, modifier = Modifier.weight(1f))
        }
    }
}

/** Status screen: link to the policy, always reachable. */
@Composable
fun PrivacySection() {
    val ctx = LocalContext.current
    Section("Privacy") {
        Hint("No account, no analytics. Settings, keys and statistics stay on this phone.")
        ShuntLink("Privacy policy", { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PRIVACY_URL))) })
    }
}
