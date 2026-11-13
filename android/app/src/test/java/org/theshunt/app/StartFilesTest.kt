package org.theshunt.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class StartFilesTest {
    /** Rests of a crashed start (OpenVPN config, torrc) go at process start, Tor's state stays. */
    @Test
    fun wipesLeftoversOnly() {
        val files = Files.createTempDirectory("shunt").toFile()
        fun put(p: String) = java.io.File(files, p).apply { parentFile!!.mkdirs(); writeText("secret") }
        val ovpn = put("openvpn/o/tunnel.ovpn")
        val torrc = put("tor/t/torrc")
        val state = put("tor/t/data/state")
        val geoip = put("tor/geoip")
        wipeStartFiles(files)
        assertFalse(ovpn.exists())
        assertFalse(torrc.exists())
        assertTrue(state.exists())
        assertTrue(geoip.exists())
        wipeStartFiles(java.io.File(files, "missing")) // no folders: nothing happens
        files.deleteRecursively()
    }
}
