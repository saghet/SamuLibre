package org.samulibre.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pruebas unitarias de enrutamiento y prevención de fuga de IP (Anti-Leak) para SamuLibre VPN.
 * Valida:
 * 1. Mapeo riguroso de nodos de salida internacionales ({us}, {ch}, {de}, {fr}, etc.).
 * 2. Clasificación estricta de dominios que requieren bypass (Meta/WhatsApp/Streaming) vs
 *    dominios que DEBEN pasar por el túnel cifrado (ej. cual-es-mi-ip.net, navegadores web).
 */
class VpnRoutingAndAntiLeakTest {

    @Test
    fun testTorExitNodesMappingCoversAllCountries() {
        assertEquals("{us}", TorManager.getExitNodesForCountry("US"))
        assertEquals("{us}", TorManager.getExitNodesForCountry("us"))
        assertEquals("{ca}", TorManager.getExitNodesForCountry("CA"))
        assertEquals("{ch}", TorManager.getExitNodesForCountry("CH"))
        assertEquals("{de}", TorManager.getExitNodesForCountry("DE"))
        assertEquals("{fr}", TorManager.getExitNodesForCountry("FR"))
        assertEquals("{nl}", TorManager.getExitNodesForCountry("NL"))
        assertEquals("{se}", TorManager.getExitNodesForCountry("SE"))
        assertEquals("{ro}", TorManager.getExitNodesForCountry("RO"))
        assertEquals("{at}", TorManager.getExitNodesForCountry("AT"))
        assertEquals("{is},{se},{no}", TorManager.getExitNodesForCountry("IS"))
        assertEquals("{no}", TorManager.getExitNodesForCountry("NO"))
        assertEquals("{pa},{cr},{ca}", TorManager.getExitNodesForCountry("PA"))
        assertEquals("{co},{pa},{cr}", TorManager.getExitNodesForCountry("CO"))
        assertEquals("{br},{cl},{ar}", TorManager.getExitNodesForCountry("BR"))
        assertEquals("{us},{ca},{ch}", TorManager.getExitNodesForCountry("UNKNOWN_XX"))
    }

    @Test
    fun testAntiLeakDomainClassification() {
        // Sitios de verificación de IP y navegación web general NUNCA deben evadir Tor (Zero-Leak)
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("cual-es-mi-ip.net"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("api.ipify.org"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("icanhazip.com"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("ifconfig.me"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("wikipedia.org"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("github.com"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("duckduckgo.com"))
        assertFalse(SamuSmartProxyServer.isTorBlockedHost("bancolombia.com"))

        // Servicios que activamente bloquean nodos Tor y requieren split-tunneling para no degradar llamadas
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("facebook.com"))
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("graph.facebook.com"))
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("whatsapp.com"))
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("web.whatsapp.com"))
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("instagram.com"))
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("netflix.com"))
        assertTrue(SamuSmartProxyServer.isTorBlockedHost("googlevideo.com"))
    }

    @Test
    fun testTunAndVpnModeCoexistenceStatus() {
        val stats = SamuVpnService.getTunStats()
        assertTrue(stats.has("is_active"))
        assertTrue(stats.has("mode"))
        assertTrue(stats.has("packets_inspected"))
        assertTrue(stats.has("packets_dropped"))
        assertTrue(stats.has("is_voice_call_active"))
        assertEquals("10.200.0.2/32", stats.getString("tun_address"))
    }
}
