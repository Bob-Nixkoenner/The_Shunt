package org.theshunt.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class LevelsTest {
    @Test
    fun migration() {
        assertEquals(Level.Simple, Level.from(null, null)) // fresh install
        assertEquals(Level.Simple, Level.from(null, false)) // old Normal
        assertEquals(Level.Pro, Level.from(null, true)) // old Pro
        assertEquals(Level.Opsec, Level.from("opsec", false)) // stored level wins
        assertEquals(Level.Simple, Level.from("simple", true))
        assertEquals(Level.Pro, Level.from("bogus", true))
        assertEquals(Level.Simple, Settings().level)
    }

    @Test
    fun table() {
        for (k in listOf("tor.add", "tor.bridges", "tor.newnym", "tor.emergency", "tor.client", "tunnel.multihop", "apps.netprofiles", "dns.servers", "checks.notes")) {
            assertFalse(k, Levels.shows(k, Level.Simple))
            assertTrue(k, Levels.shows(k, Level.Pro))
            assertTrue(k, Levels.shows(k, Level.Opsec))
        }
        for (k in listOf("opsec.band", "opsec.emergency")) {
            assertFalse(k, Levels.shows(k, Level.Simple))
            assertFalse(k, Levels.shows(k, Level.Pro))
            assertTrue(k, Levels.shows(k, Level.Opsec))
        }
        // a part not in the table shows everywhere
        assertTrue(Levels.shows("leaktest", Level.Simple))
    }

    @Test
    fun opsecOnOff() {
        val s = Settings(level = Level.Pro)
        val on = Opsec.switchOn(s, setOf("strict"))
        assertEquals(Level.Opsec, on.level)
        assertTrue(on.strictCheck)
        assertEquals(mapOf("strict" to false), on.opsecUndo)
        // undo ticked: back to how it was
        val back = Opsec.switchOff(on, Level.Simple, setOf("strict"))
        assertEquals(Level.Simple, back.level)
        assertFalse(back.strictCheck)
        assertTrue(back.opsecUndo.isEmpty())
        // keep all: stays on, nothing left to undo
        val kept = Opsec.switchOff(on, Level.Pro, emptySet())
        assertTrue(kept.strictCheck)
        assertTrue(kept.opsecUndo.isEmpty())
        // unticked in the assistant: nothing changes but the level
        val none = Opsec.switchOn(s, emptySet())
        assertFalse(none.strictCheck)
        assertTrue(none.opsecUndo.isEmpty())
        // already on: nothing to undo
        val already = Opsec.switchOn(s.copy(strictCheck = true), setOf("strict"))
        assertTrue(already.opsecUndo.isEmpty())
    }

    @Test
    fun strictFindings() {
        val wg = Tunnel("a", "")
        val ovpn = Tunnel("b", "", Tunnel.OPENVPN)
        val s = Settings(
            tunnels = listOf(wg, ovpn), defaultRoute = "direct",
            apps = mapOf("org.example.printer" to "direct", "org.example.mail" to "tunnel:a"),
            networks = listOf(NetProfile("wifi", "link:wifi")),
        )
        val fs = StrictCheck.findings(s, listOf("b")) { "Printer" }
        assertEquals(listOf("default.direct", "network.direct", "ovpn.nowrap", "rule.direct"), fs.map { it.id })
        assertEquals(listOf(true, true, true, false), fs.map { it.bad }) // direct rules stay warnings
        assertEquals(listOf("rule" to "Printer"), fs.last().args)
        // everything through Tor: routes are not used
        assertEquals(listOf("ovpn.nowrap"), StrictCheck.findings(s.copy(torAll = true), listOf("b")).map { it.id })
        // no tunnel yet: direct is all there is
        assertTrue(StrictCheck.findings(Settings(defaultRoute = "direct"), emptyList()).isEmpty())
    }

    /** The texts drawn from data (not T("…") literals the Go test finds) have a German translation. */
    @Test
    fun germanTexts() {
        val de = File("../../internal/i18n/lang/de.json").readText()
        val texts = Opsec.ITEMS.flatMap { listOf(it.text, it.help, it.note) } +
            StrictCheck.findings(
                Settings(tunnels = listOf(Tunnel("b", "", Tunnel.OPENVPN)), defaultRoute = "direct", apps = mapOf("x" to "direct"),
                    networks = listOf(NetProfile("wifi", "direct"), NetProfile("mobile", "direct"))),
                listOf("b"),
            ).map { it.msg } + Level.entries.map { it.label }
        for (t in texts.filter { it.isNotEmpty() }) assertTrue("no German for \"$t\"", de.contains("\"$t\":"))
    }
}
