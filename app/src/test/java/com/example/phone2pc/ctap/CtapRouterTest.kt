package com.example.phone2pc.ctap

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [CtapRouter].
 * Tests command routing, error handling, GetInfo response, and MakeCredential parsing.
 */
class CtapRouterTest {

    // Router without biometric handler — only tests that don't need real Keystore
    private val router = CtapRouter()

    // --- Command routing ---

    @Test
    fun `process empty message returns invalid length error`() = runBlocking {
        val response = router.process(ByteArray(0))
        assertArrayEquals(CtapErrorCode.ERR_INVALID_LENGTH.toResponse(), response)
    }

    @Test
    fun `process unknown command returns invalid command error`() = runBlocking {
        val unknownCommand = byteArrayOf(0x99.toByte())
        val response = router.process(unknownCommand)
        assertArrayEquals(CtapErrorCode.ERR_INVALID_COMMAND.toResponse(), response)
    }

    // --- GetInfo ---

    @Test
    fun `process get info returns success and valid cbor`() = runBlocking {
        val getInfoCommand = byteArrayOf(CtapCommand.GET_INFO)
        val response = router.process(getInfoCommand)

        assertEquals(CtapErrorCode.ERR_SUCCESS.code, response[0])

        val cborMap = CborDecoder(response.copyOfRange(1, response.size)).readIntKeyMap()

        val versions = cborMap[1] as List<*>
        assertEquals("FIDO_2_0", versions[0])

        val aaguid = cborMap[3] as ByteArray
        assertEquals(16, aaguid.size)

        val options = cborMap[4] as Map<*, *>
        assertEquals(true, options["rk"])
        assertEquals(true, options["up"])
        assertEquals(true, options["uv"])

        assertEquals(1024L, cborMap[5] as Long)
    }

    // --- MakeCredential parsing errors ---

    @Test
    fun `make credential with empty cbor returns invalid cbor`() = runBlocking {
        val msg = byteArrayOf(CtapCommand.MAKE_CREDENTIAL)
        val response = router.process(msg)
        assertEquals(CtapErrorCode.ERR_INVALID_CBOR.code, response[0])
    }

    @Test
    fun `make credential missing clientDataHash returns missing parameter`() = runBlocking {
        // CBOR map with no key 1 (clientDataHash)
        val cbor = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(2)
            .encodeTextString("test")
            .toByteArray()

        val msg = ByteArray(1 + cbor.size)
        msg[0] = CtapCommand.MAKE_CREDENTIAL
        System.arraycopy(cbor, 0, msg, 1, cbor.size)

        val response = router.process(msg)
        assertEquals(CtapErrorCode.ERR_MISSING_PARAMETER.code, response[0])
    }

    @Test
    fun `make credential wrong clientDataHash size returns invalid length`() = runBlocking {
        // clientDataHash must be exactly 32 bytes
        val cbor = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(1)
            .encodeByteString(ByteArray(16)) // Wrong: 16 instead of 32
            .toByteArray()

        val msg = ByteArray(1 + cbor.size)
        msg[0] = CtapCommand.MAKE_CREDENTIAL
        System.arraycopy(cbor, 0, msg, 1, cbor.size)

        val response = router.process(msg)
        assertEquals(CtapErrorCode.ERR_INVALID_LENGTH.code, response[0])
    }

    @Test
    fun `make credential missing rp returns missing parameter`() = runBlocking {
        val cbor = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(1)
            .encodeByteString(ByteArray(32))
            .toByteArray()

        val msg = ByteArray(1 + cbor.size)
        msg[0] = CtapCommand.MAKE_CREDENTIAL
        System.arraycopy(cbor, 0, msg, 1, cbor.size)

        val response = router.process(msg)
        assertEquals(CtapErrorCode.ERR_MISSING_PARAMETER.code, response[0])
    }

    @Test
    fun `make credential unsupported algorithm returns error`() = runBlocking {
        // Provide all required params but with unsupported algorithm (RS256 = -257)
        val cbor = CborEncoder()
            .encodeMapStart(4)
            .encodeUnsignedInt(1)
            .encodeByteString(ByteArray(32))
            .encodeUnsignedInt(2)
            .encodeMapStart(1).encodeTextString("id").encodeTextString("example.com")
            .encodeUnsignedInt(3)
            .encodeMapStart(1).encodeTextString("id").encodeByteString(ByteArray(8))
            .encodeUnsignedInt(4)
            .encodeArrayStart(1)
            .encodeMapStart(2)
            .encodeTextString("type").encodeTextString("public-key")
            .encodeTextString("alg").encodeNegativeInt(-257) // RS256, not supported
            .toByteArray()

        val msg = ByteArray(1 + cbor.size)
        msg[0] = CtapCommand.MAKE_CREDENTIAL
        System.arraycopy(cbor, 0, msg, 1, cbor.size)

        val response = router.process(msg)
        assertEquals(CtapErrorCode.ERR_UNSUPPORTED_ALGORITHM.code, response[0])
    }
}
