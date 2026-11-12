package org.theshunt.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DefenseTest {
    @Test
    fun oldClassesAreMigrated() {
        val s = Settings(netClasses = mapOf("wifi" to "trusted"))
        assertEquals("safe", Defense.classFor(s, "wifi")) // old "trusted" is read as safe
        assertEquals("safe", Defense.classFor(Settings(netClasses = mapOf("wifi" to "managed")), "wifi"))
        assertEquals("unknown", Defense.classFor(Settings(netClasses = mapOf("wifi" to "public")), "wifi"))
        assertEquals("unsafe", Defense.classFor(Settings(netClasses = mapOf("wifi" to "unsafe")), "wifi"))
        assertEquals("unknown", Defense.classFor(s, "mobile"))
        assertEquals("unknown", Defense.classFor(s, ""))
        assertEquals("unknown", Defense.classFor(Settings(netClasses = mapOf("wifi" to "bogus")), "wifi"))
    }

    @Test
    fun networkKeyIsAHashNeverTheName() {
        val k = Defense.netKey("wifi", "HomeNet")
        assertEquals(12, k.length)
        assertTrue(!k.contains("Home"))
        assertNotEquals(k, Defense.netKey("wifi", "Other"))
    }

    @Test
    fun defenseIsOffByDefault() {
        assertTrue(!Settings().defense)
        assertEquals("{\"enabled\":false}", Defense.configJson(Settings()))
    }

    @Test
    fun uiOnlyInMaxSecurity() {
        assertTrue(!Levels.shows("defense.ui", Level.Simple))
        assertTrue(!Levels.shows("defense.ui", Level.Pro))
        assertTrue(Levels.shows("defense.ui", Level.Opsec))
    }

    @Test
    fun detailFields() {
        val f = Defense.fields("app=org.example.app list=feodo")
        assertEquals("org.example.app", f["app"])
        assertEquals("feodo", f["list"])
    }
}
