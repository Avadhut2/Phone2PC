package com.example.phone2pc.ctap

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [CborEncoder] and [CborDecoder].
 *
 * Tests verify that encoded bytes match RFC 7049 wire format,
 * and that round-trip (encode → decode) preserves values.
 */
class CborEncoderDecoderTest {

    // --- CborEncoder Tests ---

    @Test
    fun `encode unsigned int 0`() {
        val bytes = CborEncoder().encodeUnsignedInt(0).toByteArray()
        assertEquals(1, bytes.size)
        assertEquals(0x00.toByte(), bytes[0]) // Major 0, value 0
    }

    @Test
    fun `encode unsigned int 23`() {
        val bytes = CborEncoder().encodeUnsignedInt(23).toByteArray()
        assertEquals(1, bytes.size)
        assertEquals(0x17.toByte(), bytes[0]) // Major 0, value 23
    }

    @Test
    fun `encode unsigned int 24`() {
        val bytes = CborEncoder().encodeUnsignedInt(24).toByteArray()
        assertEquals(2, bytes.size)
        assertEquals(0x18.toByte(), bytes[0]) // Major 0, additional 24
        assertEquals(24.toByte(), bytes[1])
    }

    @Test
    fun `encode unsigned int 256`() {
        val bytes = CborEncoder().encodeUnsignedInt(256).toByteArray()
        assertEquals(3, bytes.size)
        assertEquals(0x19.toByte(), bytes[0]) // Major 0, additional 25 (2-byte)
        assertEquals(0x01.toByte(), bytes[1])
        assertEquals(0x00.toByte(), bytes[2])
    }

    @Test
    fun `encode negative int -1`() {
        val bytes = CborEncoder().encodeNegativeInt(-1).toByteArray()
        assertEquals(1, bytes.size)
        assertEquals(0x20.toByte(), bytes[0]) // Major 1, value 0
    }

    @Test
    fun `encode byte string`() {
        val data = byteArrayOf(0x01, 0x02, 0x03)
        val bytes = CborEncoder().encodeByteString(data).toByteArray()
        assertEquals(0x43.toByte(), bytes[0]) // Major 2, length 3
        assertArrayEquals(data, bytes.sliceArray(1..3))
    }

    @Test
    fun `encode text string`() {
        val text = "FIDO"
        val bytes = CborEncoder().encodeTextString(text).toByteArray()
        assertEquals(0x64.toByte(), bytes[0]) // Major 3, length 4
        assertEquals("FIDO", String(bytes.sliceArray(1..4), Charsets.UTF_8))
    }

    @Test
    fun `encode empty map`() {
        val bytes = CborEncoder().encodeMapStart(0).toByteArray()
        assertEquals(1, bytes.size)
        assertEquals(0xA0.toByte(), bytes[0]) // Major 5, length 0
    }

    @Test
    fun `encode boolean true`() {
        val bytes = CborEncoder().encodeBoolean(true).toByteArray()
        assertEquals(0xF5.toByte(), bytes[0])
    }

    @Test
    fun `encode boolean false`() {
        val bytes = CborEncoder().encodeBoolean(false).toByteArray()
        assertEquals(0xF4.toByte(), bytes[0])
    }

    @Test
    fun `encode null`() {
        val bytes = CborEncoder().encodeNull().toByteArray()
        assertEquals(0xF6.toByte(), bytes[0])
    }

    // --- CborDecoder Tests ---

    @Test
    fun `decode unsigned int`() {
        val bytes = CborEncoder().encodeUnsignedInt(42).toByteArray()
        val result = CborDecoder(bytes).read()
        assertEquals(42L, result)
    }

    @Test
    fun `decode negative int`() {
        val bytes = CborEncoder().encodeNegativeInt(-5).toByteArray()
        val result = CborDecoder(bytes).read()
        assertEquals(-5L, result)
    }

    @Test
    fun `decode byte string`() {
        val original = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val bytes = CborEncoder().encodeByteString(original).toByteArray()
        val result = CborDecoder(bytes).read()
        assertArrayEquals(original, result as ByteArray)
    }

    @Test
    fun `decode text string`() {
        val bytes = CborEncoder().encodeTextString("hello").toByteArray()
        val result = CborDecoder(bytes).read()
        assertEquals("hello", result)
    }

    @Test
    fun `decode boolean`() {
        val trueBytes = CborEncoder().encodeBoolean(true).toByteArray()
        assertEquals(true, CborDecoder(trueBytes).read())

        val falseBytes = CborEncoder().encodeBoolean(false).toByteArray()
        assertEquals(false, CborDecoder(falseBytes).read())
    }

    @Test
    fun `decode null`() {
        val bytes = CborEncoder().encodeNull().toByteArray()
        assertNull(CborDecoder(bytes).read())
    }

    // --- Round-Trip: CTAP2-style integer-keyed map ---

    @Test
    fun `round trip integer-keyed map`() {
        // Encode: {1: "FIDO_2_0", 3: h'AABB'}
        val encoded = CborEncoder()
            .encodeMapStart(2)
            .encodeUnsignedInt(1)
            .encodeTextString("FIDO_2_0")
            .encodeUnsignedInt(3)
            .encodeByteString(byteArrayOf(0xAA.toByte(), 0xBB.toByte()))
            .toByteArray()

        val map = CborDecoder(encoded).readIntKeyMap()

        assertEquals(2, map.size)
        assertEquals("FIDO_2_0", map[1])
        assertArrayEquals(byteArrayOf(0xAA.toByte(), 0xBB.toByte()), map[3] as ByteArray)
    }

    @Test
    fun `round trip nested map`() {
        // Encode: {1: {2: "inner"}}
        val encoded = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(1)
            .encodeMapStart(1)
            .encodeUnsignedInt(2)
            .encodeTextString("inner")
            .toByteArray()

        val map = CborDecoder(encoded).readIntKeyMap()
        val inner = map[1] as Map<*, *>
        assertEquals("inner", inner[2L])
    }

    @Test
    fun `round trip array value`() {
        // Encode: {1: ["a", "b"]}
        val encoded = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(1)
            .encodeArrayStart(2)
            .encodeTextString("a")
            .encodeTextString("b")
            .toByteArray()

        val map = CborDecoder(encoded).readIntKeyMap()
        val arr = map[1] as List<*>
        assertEquals(listOf("a", "b"), arr)
    }

    @Test(expected = CborException::class)
    fun `decode empty data throws`() {
        CborDecoder(ByteArray(0)).read()
    }

    @Test(expected = CborException::class)
    fun `decode truncated byte string throws`() {
        // Claim 10 bytes but provide only 2
        val bad = byteArrayOf(0x4A, 0x01, 0x02) // Major 2, length 10, only 2 data bytes
        CborDecoder(bad).read()
    }
}
