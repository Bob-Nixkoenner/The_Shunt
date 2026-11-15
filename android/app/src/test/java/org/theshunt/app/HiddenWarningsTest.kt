package org.theshunt.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HiddenWarningsTest {
    private val direct = Finding(false, "rule.direct", "Rule “{rule}” sends traffic direct, past every tunnel.", listOf("rule" to "Bank"), subject = "com.bank")
    private val other = direct.copy(args = listOf("rule" to "Printer"), subject = "com.printer")

    @Test
    fun keys() {
        assertEquals("rule.direct:com.bank", HiddenWarnings.key(direct))
        // bad ones and states never get a key
        assertNull(HiddenWarnings.key(Finding(true, "ovpn.nowrap", "x", subject = "vpn")))
        assertNull(HiddenWarnings.key(Finding(true, "default.direct", "x")))
        assertNull(HiddenWarnings.key(Finding(false, "privatedns", "x")))
        assertEquals("default.block", HiddenWarnings.key(Finding(false, "default.block", "x")))
    }

    @Test
    fun expires() {
        val now = 1_000_000L
        var s = HiddenWarnings.hide(Settings(), direct, HiddenWarnings.DAY, now)
        assertTrue(HiddenWarnings.hidden(s, direct, now))
        assertFalse(HiddenWarnings.hidden(s, other, now)) // per rule
        assertTrue(HiddenWarnings.hidden(s, direct, now + HiddenWarnings.DAY - 1))
        assertFalse(HiddenWarnings.hidden(s, direct, now + HiddenWarnings.DAY))
        assertEquals(0, HiddenWarnings.active(s, now + HiddenWarnings.DAY).size)

        s = HiddenWarnings.hide(s, other, 0L, now)
        assertTrue(HiddenWarnings.hidden(s, other, now + 100 * HiddenWarnings.WEEK)) // for good
        s = HiddenWarnings.show(s, other.let { HiddenWarnings.key(it)!! }, now)
        assertFalse(HiddenWarnings.hidden(s, other, now))
        assertEquals(listOf("rule.direct:com.bank"), HiddenWarnings.active(s, now).map { it.key })
    }

    @Test
    fun badNeverHidden() {
        val bad = Finding(true, "ovpn.nowrap", "x", subject = "vpn")
        val s = HiddenWarnings.hide(Settings(), bad, 0L, 1L)
        assertEquals(Settings(), s)
        assertFalse(HiddenWarnings.hidden(s, bad, 1L))
    }
}
