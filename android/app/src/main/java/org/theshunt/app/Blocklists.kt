package org.theshunt.app

import android.content.Context
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * DNS filter lists, the same ones the desktop uses (RPiList, thank you).
 * Downloaded by the app itself – it is excluded from its own VPN, so this
 * goes out directly – and refreshed once a day when the VPN starts.
 */
object Blocklists {
    const val SOURCE = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/"

    /** Name to short description; the first two are on by default. */
    val ALL = linkedMapOf(
        "easylist" to "Ads",
        "Phishing-Angriffe" to "Phishing",
        "notserious" to "Dubious sites",
        "Fake-Science" to "Fake science",
        "Corona-Blocklist" to "Corona fakes",
        "spam.mails" to "Spam senders",
        "malware" to "Malware",
        "Win10Telemetry" to "Windows telemetry",
        "crypto" to "Crypto miners",
    )
    val DEFAULT = listOf("easylist", "Phishing-Angriffe")

    private const val MAX_AGE_MS = 24 * 3600 * 1000L

    fun file(ctx: Context, name: String) = File(File(ctx.filesDir, "blocklists"), name)

    /** Downloads missing and day-old lists; an old copy is kept if the download fails. */
    fun refresh(ctx: Context, names: Collection<String>) {
        for (name in names) {
            val f = file(ctx, name)
            if (f.exists() && System.currentTimeMillis() - f.lastModified() < MAX_AGE_MS) continue
            try {
                f.parentFile?.mkdirs()
                val tmp = File(f.path + ".part")
                val c = URL(SOURCE + name).openConnection() as HttpURLConnection
                c.connectTimeout = 10_000
                c.readTimeout = 30_000
                c.inputStream.use { input -> tmp.outputStream().use { input.copyTo(it) } }
                if (c.responseCode != 200) throw IllegalStateException("HTTP ${c.responseCode}")
                tmp.renameTo(f)
            } catch (e: Exception) {
                Log.w("Shunt", "blocklist $name: ${e.message}")
            }
        }
    }
}
