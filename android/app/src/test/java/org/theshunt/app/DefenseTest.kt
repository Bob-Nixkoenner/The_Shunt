package org.theshunt.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DefenseTest {
    @Test
    fun unknownNetworkIsPublic() {
        val s = Settings(netClasses = mapOf("wifi" to "trusted"))
        assertEquals("trusted", Defense.classFor(s, "wifi"))
        assertEquals("public", Defense.classFor(s, "mobile"))
        assertEquals("public", Defense.classFor(s, ""))
        assertEquals("public", Defense.classFor(Settings(netClasses = mapOf("wifi" to "bogus")), "wifi"))
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
