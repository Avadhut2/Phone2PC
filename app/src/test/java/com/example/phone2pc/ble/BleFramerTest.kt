package com.example.phone2pc.ble

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [BleFramer] — FIDO BLE fragmentation and reassembly.
 *
 * These tests verify correctness of the FIDO BLE framing protocol:
 *   - Single-frame messages (payload fits in one init packet)
 *   - Multi-frame messages (payload requires continuation packets)
 *   - Zero-length payloads
 *   - Round-trip: fragment then reassemble must yield original
 *   - Error cases: empty packet, out-of-sequence, missing init
 */
class BleFramerTest {

    private lateinit var framer: BleFramer

    @Before
    fun setUp() {
        framer = BleFramer()
    }

    // --- Fragmentation Tests ---

    @Test
    fun `fragment single frame - payload fits in init packet`() {
        val cmd: Byte = 0x83.toByte()
        val data = byteArrayOf(0x01, 0x02, 0x03)
        val mtu = 20 // init can hold 17 data bytes, so 3 bytes fits easily

        val frames = framer.fragment(cmd, data, mtu)

        assertEquals(1, frames.size)
        // Header: CMD, HLEN=0, LLEN=3
        assertEquals(cmd, frames[0][0])
        assertEquals(0x00.toByte(), frames[0][1])
        assertEquals(0x03.toByte(), frames[0][2])
        // Data
        assertArrayEquals(data, frames[0].sliceArray(3 until 6))
    }

    @Test
    fun `fragment multi frame - payload spans init and continuation`() {
        val cmd: Byte = 0x83.toByte()
        val data = ByteArray(10) { it.toByte() } // 0..9
        val mtu = 7 // init holds 4 data bytes, cont holds 6 data bytes

        val frames = framer.fragment(cmd, data, mtu)

        // Init frame: 3 header + 4 data = 7 bytes
        assertEquals(7, frames[0].size)
        // Cont frame 0: 1 header + 6 data = 7 bytes (carries bytes 4..9)
        assertEquals(7, frames[1].size)
        assertEquals(0x00.toByte(), frames[1][0]) // SEQ = 0
        assertEquals(2, frames.size)
    }

    @Test
    fun `fragment zero length payload`() {
        val cmd: Byte = 0x83.toByte()
        val data = ByteArray(0)
        val mtu = 20

        val frames = framer.fragment(cmd, data, mtu)

        assertEquals(1, frames.size)
        assertEquals(3, frames[0].size) // Just the 3-byte header
        assertEquals(0x00.toByte(), frames[0][1]) // HLEN
        assertEquals(0x00.toByte(), frames[0][2]) // LLEN
    }

    // --- Reassembly Tests ---

    @Test
    fun `accumulate single init packet completes immediately`() {
        val cmd: Byte = 0x83.toByte()
        val payload = byteArrayOf(0xAA.toByte(), 0xBB.toByte())

        // Build init packet: CMD | HLEN=0 | LLEN=2 | data
        val packet = byteArrayOf(cmd, 0x00, 0x02, 0xAA.toByte(), 0xBB.toByte())

        val result = framer.accumulate(packet)

        assertNotNull(result)
        assertEquals(cmd, result!![0])
        assertArrayEquals(payload, result.sliceArray(1 until result.size))
    }

    @Test
    fun `accumulate multi frame reassembles correctly`() {
        val cmd: Byte = 0x83.toByte()
        val payload = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)

        // Init: CMD | HLEN=0 | LLEN=5 | first 2 bytes of data
        val init = byteArrayOf(cmd, 0x00, 0x05, 0x01, 0x02)
        assertNull(framer.accumulate(init)) // Not done yet

        // Cont 0: SEQ=0 | next 3 bytes of data
        val cont = byteArrayOf(0x00, 0x03, 0x04, 0x05)
        val result = framer.accumulate(cont)

        assertNotNull(result)
        assertEquals(cmd, result!![0])
        assertArrayEquals(payload, result.sliceArray(1 until result.size))
    }

    @Test
    fun `accumulate zero length payload`() {
        val cmd: Byte = 0x83.toByte()
        val packet = byteArrayOf(cmd, 0x00, 0x00)  // Zero length

        val result = framer.accumulate(packet)

        assertNotNull(result)
        assertEquals(1, result!!.size) // Just the CMD byte
        assertEquals(cmd, result[0])
    }

    // --- Round-Trip Test ---

    @Test
    fun `round trip - fragment then reassemble recovers original`() {
        val cmd: Byte = 0x83.toByte()
        val original = ByteArray(100) { (it * 3).toByte() }
        val mtu = 20

        val frames = framer.fragment(cmd, original, mtu)

        var result: ByteArray? = null
        for (frame in frames) {
            result = framer.accumulate(frame)
        }

        assertNotNull(result)
        assertEquals(cmd, result!![0])
        assertArrayEquals(original, result.sliceArray(1 until result.size))
    }

    // --- Error Cases ---

    @Test(expected = IllegalArgumentException::class)
    fun `accumulate empty packet throws`() {
        framer.accumulate(ByteArray(0))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `accumulate continuation without init throws`() {
        // SEQ=0, data — but no init has been received
        framer.accumulate(byteArrayOf(0x00, 0x01, 0x02))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `accumulate out of sequence throws`() {
        val cmd: Byte = 0x83.toByte()
        val init = byteArrayOf(cmd, 0x00, 0x0A, 0x01, 0x02) // expects 10 bytes, sent 2
        framer.accumulate(init)

        // Send SEQ=1 instead of SEQ=0
        framer.accumulate(byteArrayOf(0x01, 0x03, 0x04))
    }

    @Test
    fun `reset clears partial state`() {
        val cmd: Byte = 0x83.toByte()
        val init = byteArrayOf(cmd, 0x00, 0x0A, 0x01, 0x02)
        assertNull(framer.accumulate(init)) // Partial

        framer.reset()

        // After reset, a fresh init should work cleanly
        val freshInit = byteArrayOf(cmd, 0x00, 0x01, 0xFF.toByte())
        val result = framer.accumulate(freshInit)
        assertNotNull(result)
        assertEquals(0xFF.toByte(), result!![1])
    }
}
