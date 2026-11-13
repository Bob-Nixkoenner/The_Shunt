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

    @Test
    fun wifiIdIsAHashOfTheName() {
        val id = Defense.wifiId("ExampleNet")
        assertTrue(Defense.isWifiId(id))
        assertTrue(!id.contains("Example"))
        assertEquals(id, Defense.wifiId("ExampleNet"))
        assertNotEquals(id, Defense.wifiId("OtherNet"))
        assertEquals("wifi:$id", Defense.wifiKey("ExampleNet"))
    }

    @Test
    fun classPerWifiFallsBackToTheWifiRow() {
        // old settings: the "wifi" class stays and is the default for every Wi-Fi
        val old = Settings(netClasses = mapOf("wifi" to "trusted"))
        assertEquals("safe", Defense.classFor(old, "wifi", "ExampleNet"))
        val s = old.copy(netClasses = old.netClasses + (Defense.wifiKey("ExampleNet") to "unsafe"))
        assertEquals("unsafe", Defense.classFor(s, "wifi", "ExampleNet"))
        assertEquals("safe", Defense.classFor(s, "wifi", "OtherNet")) // not rated: the Wi-Fi row
        assertEquals("safe", Defense.classFor(s, "wifi")) // name not known (no permission)
        assertEquals("unknown", Defense.classFor(Settings(), "wifi", "ExampleNet")) // nothing rated: unclear
        assertEquals("unknown", Defense.classFor(s, "mobile", "ExampleNet")) // a name only counts on Wi-Fi
        assertEquals(listOf(Defense.wifiId("ExampleNet")), Defense.knownWifis(s))
    }

    @Test
    fun wifiProfileKeepsOnlyTheIdAndComesFirst() {
        val id = Defense.wifiId("ExampleNet")
        val s = Settings(networks = listOf(NetProfile("wifi", "direct"), NetProfile("wifi", "block", id)))
        val j = s.toJson().getJSONArray("networks")
        assertEquals(id, j.getJSONObject(0).getJSONArray("ssid").getString(0)) // one Wi-Fi before all Wi-Fi
        assertTrue(!j.toString().contains("ExampleNet"))
        assertEquals(s.networks.toSet(), (0 until j.length()).map { NetProfile.fromJson(j.getJSONObject(it)) }.toSet())
        assertEquals(listOf(id), Defense.knownWifis(s))
    }

    @Test
    fun filterListsPerWifi() {
        val id = Defense.wifiId("ExampleNet")
        val some = Blocklists.ALL.keys.take(2)
        val s = Settings(filterLists = some.take(1), networks = listOf(NetProfile("wifi", "", id, some), NetProfile("wifi", "", Defense.wifiId("OtherNet"), emptyList())))
        val j = s.toJson().getJSONArray("networks")
        val back = (0 until j.length()).map { NetProfile.fromJson(j.getJSONObject(it)) }
        assertEquals(s.networks.toSet(), back.toSet()) // own lists and "none here" (empty) survive
        assertEquals(null, NetProfile.fromJson(NetProfile("wifi", "direct").toJson()).lists) // no own lists: as everywhere
        assertEquals(some.toSet(), s.allFilterLists().toSet()) // all lists in use are downloaded
        assertEquals(emptyList<String>(), NetProfile.fromJson(org.json.JSONObject("{\"link\":\"wifi\",\"lists\":[\"no-such-list\"]}")).lists)
    }

    @Test
    fun wifiListFromProOnSimpleStaysDefault() {
        assertEquals(Level.Simple, Settings().level)
        assertTrue(!Levels.shows("wifi.list", Level.Simple))
        assertTrue(Levels.shows("wifi.list", Level.Pro))
        assertTrue(Levels.shows("wifi.list", Level.Opsec))
    }
}
