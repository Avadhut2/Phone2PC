package com.example.phone2pc.ctap

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest

/**
 * Unit tests for [AuthenticatorData].
 * Verifies binary layout matches WebAuthn §6.1 exactly.
 */
class AuthenticatorDataTest {

    @Test
    fun `assertion data is exactly 37 bytes`() {
        val data = AuthenticatorData.buildForAssertion("example.com", signCount = 0)
        assertEquals(37, data.size)
    }

    @Test
    fun `assertion data starts with rpIdHash`() {
        val rpId = "example.com"
        val expectedHash = MessageDigest.getInstance("SHA-256")
            .digest(rpId.toByteArray(Charsets.UTF_8))

        val data = AuthenticatorData.buildForAssertion(rpId, signCount = 0)
        assertArrayEquals(expectedHash, data.copyOfRange(0, 32))
    }

    @Test
    fun `assertion flags have UP and UV set`() {
        val data = AuthenticatorData.buildForAssertion(
            "example.com", signCount = 0, userPresent = true, userVerified = true
        )
        val flags = data[32].toInt() and 0xFF
        assertEquals(0x05, flags) // UP (0x01) | UV (0x04)
    }

    @Test
    fun `assertion flags only UP when UV is false`() {
        val data = AuthenticatorData.buildForAssertion(
            "example.com", signCount = 0, userPresent = true, userVerified = false
        )
        val flags = data[32].toInt() and 0xFF
        assertEquals(0x01, flags) // UP only
    }

    @Test
    fun `sign count is big-endian at bytes 33-36`() {
        val data = AuthenticatorData.buildForAssertion("example.com", signCount = 258)
        // 258 = 0x00000102
        assertEquals(0x00.toByte(), data[33])
        assertEquals(0x00.toByte(), data[34])
        assertEquals(0x01.toByte(), data[35])
        assertEquals(0x02.toByte(), data[36])
    }

    @Test
    fun `registration data includes AT flag`() {
        val aaguid = ByteArray(16)
        val credId = byteArrayOf(0x01, 0x02, 0x03)
        val coseKey = byteArrayOf(0xAA.toByte(), 0xBB.toByte())

        val data = AuthenticatorData.buildForRegistration(
            "example.com", signCount = 0, aaguid, credId, coseKey
        )
        val flags = data[32].toInt() and 0xFF
        assertEquals(0x45, flags) // UP (0x01) | UV (0x04) | AT (0x40)
    }

    @Test
    fun `registration data has correct attested credential layout`() {
        val aaguid = ByteArray(16) { it.toByte() } // 0x00..0x0F
        val credId = byteArrayOf(0xDE.toByte(), 0xAD.toByte())
        val coseKey = byteArrayOf(0xCA.toByte(), 0xFE.toByte())

        val data = AuthenticatorData.buildForRegistration(
            "example.com", signCount = 1, aaguid, credId, coseKey
        )

        // After 37 bytes of header, attested credential data starts:
        // aaguid (16 bytes)
        assertArrayEquals(aaguid, data.copyOfRange(37, 53))

        // credentialIdLength (2 bytes big-endian) = 2
        assertEquals(0x00.toByte(), data[53])
        assertEquals(0x02.toByte(), data[54])

        // credentialId
        assertEquals(0xDE.toByte(), data[55])
        assertEquals(0xAD.toByte(), data[56])

        // cosePublicKey
        assertEquals(0xCA.toByte(), data[57])
        assertEquals(0xFE.toByte(), data[58])

        // Total = 37 + 16 + 2 + 2 + 2 = 59
        assertEquals(59, data.size)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `registration rejects wrong aaguid size`() {
        AuthenticatorData.buildForRegistration(
            "example.com", 0, ByteArray(10), byteArrayOf(), byteArrayOf()
        )
    }

    @Test
    fun `hashRpId produces correct SHA-256`() {
        val hash = AuthenticatorData.hashRpId("example.com")
        assertEquals(32, hash.size)
        // Verify it matches java.security directly
        val expected = MessageDigest.getInstance("SHA-256")
            .digest("example.com".toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected, hash)
    }
}
