package org.theshunt.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FilterExtrasTest {
    @Test fun siteNames() {
        assertEquals("example.com", allowName("https://www.Example.com/path?x=1"))
        assertEquals("a.example.com", allowName("||a.example.com^"))
        assertEquals("example.com", allowName(" example.com. "))
        assertNull(allowName("localhost"))
        assertNull(allowName("not a name"))
        assertNull(allowName(""))
    }

    @Test fun allowTextGrowsOnce() {
        val a = withAllowed("", "example.com")
        assertEquals("||example.com^\n", a)
        assertEquals(a, withAllowed(a, "example.com")) // already in: unchanged
        assertEquals("@@||example.com^\n", withAllowed("@@||example.com^\n", "example.com"))
        assertEquals("# mine\n||a.test^\n", withAllowed("# mine", "a.test"))
    }

    @Test fun customListNames() {
        assertEquals("my-ads", Blocklists.customName("Ads", emptyList()))
        assertEquals("my-ads2", Blocklists.customName("ads", listOf("my-ads")))
        assertEquals("my-list", Blocklists.customName("###", emptyList()))
        assert(Blocklists.known("my-x") && Blocklists.known("hagezi-pro") && !Blocklists.known("evil"))
    }
}
