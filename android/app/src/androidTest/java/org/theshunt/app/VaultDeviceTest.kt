package org.theshunt.app

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The vault on a real AndroidKeyStore: an old settings.json with keys in clear is
 * moved into the key store on load, reads back, and without the key the tunnels
 * are locked and fail closed. Runs on a device or an emulator (-no-window is enough):
 *   ./gradlew connectedPlayDebugAndroidTest
 * It replaces the app's settings.json and key: only on a test device.
 */
@RunWith(AndroidJUnit4::class)
class VaultDeviceTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private val file get() = File(ctx.filesDir, "settings.json")
    private val wgKey = "TESTPRIVATEKEYTESTPRIVATEKEYTESTPRIVATE12="
    private val conf = "[Interface]\nPrivateKey = $wgKey\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = PUB\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"

    @Before
    fun clean() {
        file.delete()
        Vault.deleteKeystoreKey()
    }

    @After
    fun cleanAfter() = clean()

    @Test
    fun clearFileIsMovedIntoTheKeyStore() {
        val s = Settings(
            tunnels = listOf(Tunnel("wg", conf), Tunnel("ovpn", "client\n<key>\nSECRETOVPN\n</key>\n", Tunnel.OPENVPN, "u", "SECRETPASS")),
            defaultRoute = "tunnel:wg",
        )
        file.writeText(s.toJson().toString(2)) // the format before the vault
        val loaded = Store.load(ctx, Vault.androidKeystore())
        assertEquals(s.tunnels, loaded.tunnels)
        val text = file.readText()
        assertFalse(text.contains(wgKey))
        assertFalse(text.contains("SECRETPASS"))
        assertFalse(text.contains("SECRETOVPN"))
        assertFalse(Settings.hasClearSecrets(JSONObject(text)))
        Vault.keystoreKeyInfo()?.let { Log.i("ShuntTest", "vault key: secure hardware=${it.isInsideSecureHardware}, level=${it.securityLevel}") }
        // a new process (empty cache) reads it with the key store key
        assertEquals(s.tunnels, Store.load(ctx, Vault.androidKeystore()).tunnels)
    }

    @Test
    fun withoutTheKeyTunnelsAreLockedAndBlock() {
        val s = Settings(tunnels = listOf(Tunnel("wg", conf)), defaultRoute = "tunnel:wg", apps = mapOf("a.b" to "tunnel:wg"))
        Store.save(ctx, s, Vault.androidKeystore())
        Vault.deleteKeystoreKey() // as on another phone
        val locked = Store.load(ctx, Vault.androidKeystore())
        assertTrue(locked.tunnels.single().locked)
        val core = JSONObject(locked.coreJson(ctx))
        assertEquals("block", core.getString("default"))
        assertEquals(0, core.getJSONArray("tunnels").length())
        // saving again keeps the sealed value (nothing lost, nothing in clear)
        val before = JSONObject(file.readText()).getJSONArray("tunnels").getJSONObject(0).getString("secret")
        Store.save(ctx, locked, Vault.androidKeystore())
        assertEquals(before, JSONObject(file.readText()).getJSONArray("tunnels").getJSONObject(0).getString("secret"))
        // a new import works with a new key
        val again = locked.copy(tunnels = listOf(Tunnel("wg2", conf)))
        Store.save(ctx, again, Vault.androidKeystore())
        assertNotNull(Store.load(ctx, Vault.androidKeystore()).tunnels.single().conf.takeIf { it == conf })
    }
}
