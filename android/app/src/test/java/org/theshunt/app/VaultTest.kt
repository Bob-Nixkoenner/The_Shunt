package org.theshunt.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * The vault with a software AES key in place of the Android Keystore (JVM tests
 * have no key store): sealing, opening, a missing or foreign key, damaged data,
 * the settings.json format and the fail-closed routes of locked tunnels.
 */
class VaultTest {
    private fun aes(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    /** A key store holding [key] (null: empty, like a new phone); counts key look-ups. */
    private class FakeKeystore(var key: SecretKey?, private val makeKey: () -> SecretKey) {
        var lookups = 0
        val vault = Vault { create ->
            lookups++
            key ?: if (create) makeKey().also { key = it } else null
        }
    }

    private val wgKey = "PRIVATEKEYPRIVATEKEYPRIVATEKEYPRIVATEKEY12="
    private val psk = "PRESHAREDPRESHAREDPRESHAREDPRESHARED12345="
    private val wgConf = "[Interface]\nPrivateKey = $wgKey\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = PUB\nPresharedKey = $psk\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\n"
    private val ovpn = Tunnel("ovpn", "client\nremote vpn.example.org 1194\n<key>\nSECRETOVPNKEY\n</key>\n", Tunnel.OPENVPN, "user1", "pass-secret-1")
    private val tor = Tunnel("tor", "client = builtin\nbridge = obfs4 192.0.2.1:443 FINGERPRINT cert=SECRETBRIDGECERT\n", Tunnel.TOR)

    private fun settings() = Settings(
        tunnels = listOf(Tunnel("wg", wgConf), ovpn, tor, Tunnel("hop", "x", Tunnel.OPENVPN, via = "wg", inbound = listOf("tcp/1716"))),
        defaultRoute = "tunnel:wg",
        apps = mapOf("a.b" to "tunnel:ovpn", "c.d" to "tunnel:hop", "e.f" to "direct"),
        networks = listOf(NetProfile("wifi", "tunnel:wg")),
    )

    /** fromJson reads dns_servers through android.net (not in JVM tests): the defaults are enough here. */
    private fun read(o: JSONObject, v: Vault?) = Settings.fromJson(JSONObject(o.toString()).apply { remove("dns_servers") }, v)

    @Test
    fun sealOpensAgainAndHidesThePlaintext() {
        val v = FakeKeystore(aes(), ::aes).vault
        val sealed = v.seal(wgConf)
        assertTrue(sealed.startsWith(Vault.PREFIX))
        assertFalse(sealed.contains(wgKey))
        assertEquals(wgConf, v.open(sealed))
        // IV + tag: at least 28 bytes more than the text
        assertTrue(Base64.getDecoder().decode(sealed.removePrefix(Vault.PREFIX)).size >= wgConf.toByteArray().size + 28)
    }

    @Test
    fun freshIvPerSealAndAnotherProcessOpensIt() {
        val key = aes()
        val a = FakeKeystore(key, ::aes).vault.seal("same")
        val b = FakeKeystore(key, ::aes).vault.seal("same")
        assertNotEquals(a, b) // new IV each time (no cache shared between the two)
        assertEquals("same", FakeKeystore(key, ::aes).vault.open(a))
        assertEquals("same", FakeKeystore(key, ::aes).vault.open(b))
    }

    @Test
    fun foreignMissingKeyOrDamagedDataGiveNullNotACrash() {
        val sealed = FakeKeystore(aes(), ::aes).vault.seal(wgConf)
        assertNull(FakeKeystore(aes(), ::aes).vault.open(sealed)) // another phone's key
        val empty = FakeKeystore(null, ::aes)
        assertNull(empty.vault.open(sealed)) // no key at all (restored copy, new phone)
        assertNull(empty.key) // opening never makes a key
        val v = FakeKeystore(aes(), ::aes).vault
        val ok = v.seal("text")
        val raw = Base64.getDecoder().decode(ok.removePrefix(Vault.PREFIX))
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 1).toByte()
        assertNull(v.open(Vault.PREFIX + Base64.getEncoder().encodeToString(raw)))
        assertNull(v.open("v1:!!notbase64"))
        assertNull(v.open("v1:AAAA"))
        assertNull(v.open("plain text"))
        // a key store that throws (not ready yet): locked, not a crash
        assertNull(Vault { throw IllegalStateException("key store busy") }.open(ok))
    }

    @Test
    fun tamperedCiphertextDoesNotOpenWithTheRightKey() {
        val key = aes()
        val ok = FakeKeystore(key, ::aes).vault.seal("text")
        val raw = Base64.getDecoder().decode(ok.removePrefix(Vault.PREFIX))
        raw[14] = (raw[14].toInt() xor 1).toByte()
        assertNull(FakeKeystore(key, ::aes).vault.open(Vault.PREFIX + Base64.getEncoder().encodeToString(raw)))
    }

    @Test
    fun sealWithoutKeyStoreThrowsSoNothingIsWrittenInClear() {
        val v = Vault { null }
        val e = runCatching { v.seal("x") }.exceptionOrNull()
        assertTrue(e is IllegalStateException)
        val s = settings()
        assertTrue(runCatching { s.toStoreJson(v) }.isFailure)
    }

    @Test
    fun cacheSavesKeyStoreCalls() {
        val ks = FakeKeystore(aes(), ::aes)
        val sealed = ks.vault.seal("abc")
        assertEquals(sealed, ks.vault.seal("abc")) // the same text keeps its sealed value: no new write
        assertEquals("abc", ks.vault.open(sealed))
        assertEquals(1, ks.lookups)
    }

    @Test
    fun settingsFileHoldsNoKeyInClearAndReadsBack() {
        val v = FakeKeystore(aes(), ::aes).vault
        val s = settings()
        val stored = s.toStoreJson(v)
        val text = stored.toString(2)
        for (secret in listOf(wgKey, psk, "SECRETOVPNKEY", "pass-secret-1", "SECRETBRIDGECERT", "user1", "vpn.example.org")) {
            assertFalse("$secret in settings.json", text.contains(secret))
        }
        assertFalse(Settings.hasClearSecrets(stored))
        // names, types, via and inbound stay readable (the UI shows them without the key)
        val t0 = stored.getJSONArray("tunnels").getJSONObject(3)
        assertEquals("hop", t0.getString("name"))
        assertEquals("wg", t0.getString("via"))
        assertEquals(Tunnel.OPENVPN, t0.getString("type"))
        assertEquals(s.tunnels, read(stored, v).tunnels)
        // the core still gets the keys (in memory only)
        assertTrue(s.toJson().toString().contains(wgKey))
    }

    @Test
    fun oldClearFileIsReadAndRecognisedForMigration() {
        val s = settings()
        val old = s.toJson() // the format before the vault: conf/user/pass in clear
        assertTrue(Settings.hasClearSecrets(old))
        val back = read(old, FakeKeystore(null, ::aes).vault)
        assertEquals(s.tunnels, back.tunnels)
        assertTrue(back.tunnels.none { it.locked })
        assertFalse(Settings.hasClearSecrets(Settings().toJson()))
    }

    @Test
    fun lockedTunnelKeepsItsSealedValueOnSave() {
        val v1 = FakeKeystore(aes(), ::aes).vault
        val stored = settings().toStoreJson(v1)
        // another phone: its own key, the old values do not open
        val v2 = FakeKeystore(aes(), ::aes).vault
        val s2 = read(stored, v2)
        assertTrue(s2.tunnels.all { it.locked && it.conf.isEmpty() && it.pass.isEmpty() })
        assertEquals(listOf("wg", "ovpn", "tor", "hop"), s2.tunnels.map { it.name })
        // a new tunnel added there, renamed one: saved, the locked ones unchanged
        val s3 = Store.rename(s2.copy(tunnels = s2.tunnels + Tunnel("new", wgConf)), "wg", "wg2")
        val stored3 = s3.toStoreJson(v2)
        val oldSecret = stored.getJSONArray("tunnels").getJSONObject(0).getString("secret")
        assertEquals(oldSecret, stored3.getJSONArray("tunnels").getJSONObject(0).getString("secret"))
        assertEquals("wg2", stored3.getJSONArray("tunnels").getJSONObject(0).getString("name"))
        // back on the first phone everything opens again, the new one is locked there
        val s4 = read(stored3, v1)
        assertEquals(wgConf, s4.tunnels.first { it.name == "wg2" }.conf)
        assertEquals("pass-secret-1", s4.tunnels.first { it.name == "ovpn" }.pass)
        assertTrue(s4.tunnels.first { it.name == "new" }.locked)
    }

    @Test
    fun lockedTunnelsFailClosed() {
        val s = settings()
        val locked = s.copy(tunnels = s.tunnels.map { if (it.name == "wg") it.copy(conf = "", sealed = "v1:x") else it })
        val c = locked.withoutLocked()
        // wg is locked and hop goes through it: both gone, their routes block
        assertEquals(listOf("ovpn", "tor"), c.tunnels.map { it.name })
        assertEquals("block", c.defaultRoute)
        assertEquals("block", c.apps["c.d"])
        assertEquals("tunnel:ovpn", c.apps["a.b"])
        assertEquals("direct", c.apps["e.f"])
        assertEquals("block", c.networks.single().route)
        assertTrue(c.toJson().toString().let { !it.contains("\"wg\"") && !it.contains("\"hop\"") })
        // nothing locked: unchanged
        assertTrue(s.withoutLocked() === s)
    }

    @Test
    fun torForEverythingOnALockedTorTunnelBlocksEverything() {
        val s = settings().let { s -> s.copy(torAll = true, tunnels = s.tunnels.map { if (it.isTor) it.copy(conf = "", sealed = "v1:x") else it }) }
        val c = s.withoutLocked()
        assertFalse(c.torAll)
        assertEquals("block", c.defaultRoute)
        assertTrue(c.apps.values.all { it == "block" })
        assertTrue(c.networks.isEmpty())
    }

    @Test
    fun wipeOverwritesTheOldBytes() {
        val f = File.createTempFile("settings", ".json")
        try {
            f.writeText("{\"conf\":\"PrivateKey = $wgKey\"}")
            val n = f.length()
            RandomAccessFile(f, "rw").use { Store.wipe(it) }
            val bytes = f.readBytes()
            assertEquals(n, bytes.size.toLong())
            assertTrue(bytes.all { it == 0.toByte() })
        } finally {
            f.delete()
        }
    }
}
