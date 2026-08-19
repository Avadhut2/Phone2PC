package com.example.phone2pc.ble

/**
 * BleFramer
 *
 * Implements the FIDO BLE fragmentation and reassembly protocol as defined by
 * the FIDO Alliance CTAP2 BLE specification.
 *
 * Frame formats:
 *   Initialization: CMD (1 byte) | HLEN (1 byte) | LLEN (1 byte) | DATA[0..n]
 *   Continuation:   SEQ (1 byte) | DATA[n+1..]
 *
 * CMD byte has bit 7 set (0x80+). SEQ starts at 0 and increments per continuation frame.
 * The total payload length is encoded as big-endian uint16 across HLEN and LLEN.
 *
 * Security: Malformed or out-of-sequence frames are rejected immediately.
 * No partial state is retained after a framing error.
 */
class BleFramer {

    // Init frame header = 3 bytes (CMD + HLEN + LLEN)
    // Continuation frame header = 1 byte (SEQ)
    companion object {
        private const val INIT_HEADER_SIZE = 3
        private const val CONT_HEADER_SIZE = 1
        private const val MAX_SEQ = 0x7F
    }

    // Reassembly state
    private var expectedCmd: Byte = 0
    private var expectedLength: Int = 0
    private var buffer: ByteArray? = null
    private var offset: Int = 0
    private var nextSeq: Int = 0

    /**
     * Fragment a complete FIDO message [data] into BLE packets no larger than [mtu] bytes.
     *
     * @param cmd  The FIDO command byte (e.g., 0x83 for MSG). Must have bit 7 set.
     * @param data The full serialized CTAP2 payload.
     * @param mtu  The negotiated BLE MTU size. Must be >= 4 (3-byte header + at least 1 data byte).
     * @return     An ordered list of byte arrays ready to be sent sequentially.
     */
    fun fragment(cmd: Byte, data: ByteArray, mtu: Int): List<ByteArray> {
        require(mtu >= INIT_HEADER_SIZE + 1) { "MTU must be at least ${INIT_HEADER_SIZE + 1}" }
        require(data.size <= 0xFFFF) { "Payload exceeds max FIDO BLE message size (65535)" }

        val frames = mutableListOf<ByteArray>()
        val initDataCapacity = mtu - INIT_HEADER_SIZE
        val contDataCapacity = mtu - CONT_HEADER_SIZE

        // Build initialization frame
        val initDataSize = minOf(initDataCapacity, data.size)
        val initFrame = ByteArray(INIT_HEADER_SIZE + initDataSize)
        initFrame[0] = cmd
        initFrame[1] = (data.size shr 8 and 0xFF).toByte()  // HLEN
        initFrame[2] = (data.size and 0xFF).toByte()         // LLEN
        data.copyInto(initFrame, INIT_HEADER_SIZE, 0, initDataSize)
        frames.add(initFrame)

        // Build continuation frames
        var dataOffset = initDataSize
        var seq = 0
        while (dataOffset < data.size) {
            require(seq <= MAX_SEQ) { "Too many continuation frames (seq overflow)" }
            val contDataSize = minOf(contDataCapacity, data.size - dataOffset)
            val contFrame = ByteArray(CONT_HEADER_SIZE + contDataSize)
            contFrame[0] = seq.toByte()
            data.copyInto(contFrame, CONT_HEADER_SIZE, dataOffset, dataOffset + contDataSize)
            frames.add(contFrame)
            dataOffset += contDataSize
            seq++
        }

        return frames
    }

    /**
     * Accumulate an incoming BLE [packet] and return the complete reassembled
     * FIDO message once all fragments have been received. Returns null if
     * more packets are expected. The returned ByteArray starts with the CMD byte
     * followed by the full payload.
     *
     * @throws IllegalArgumentException if the packet is malformed or out of sequence.
     */
    fun accumulate(packet: ByteArray): ByteArray? {
        require(packet.isNotEmpty()) { "Empty packet" }

        val firstByte = packet[0].toInt() and 0xFF
        val isInit = (firstByte and 0x80) != 0

        return if (isInit) {
            accumulateInit(packet)
        } else {
            accumulateCont(packet)
        }
    }

    /** Reset internal reassembly state (call on disconnect or error). */
    fun reset() {
        buffer = null
        offset = 0
        nextSeq = 0
        expectedCmd = 0
        expectedLength = 0
    }

    private fun accumulateInit(packet: ByteArray): ByteArray? {
        require(packet.size >= INIT_HEADER_SIZE) { "Init packet too short" }

        // If we had a partial reassembly in progress, discard it (spec behavior).
        reset()

        expectedCmd = packet[0]
        expectedLength = ((packet[1].toInt() and 0xFF) shl 8) or (packet[2].toInt() and 0xFF)

        if (expectedLength == 0) {
            // Zero-length payload: return CMD + empty payload immediately.
            return byteArrayOf(expectedCmd)
        }

        buffer = ByteArray(expectedLength)
        val dataSize = minOf(packet.size - INIT_HEADER_SIZE, expectedLength)
        packet.copyInto(buffer!!, 0, INIT_HEADER_SIZE, INIT_HEADER_SIZE + dataSize)
        offset = dataSize

        return completeIfDone()
    }

    private fun accumulateCont(packet: ByteArray): ByteArray? {
        val buf = buffer
        require(buf != null) { "Continuation packet without preceding init" }
        require(packet.size >= CONT_HEADER_SIZE + 1) { "Continuation packet too short" }

        val seq = packet[0].toInt() and 0xFF
        require(seq == nextSeq) { "Out-of-sequence: expected $nextSeq, got $seq" }
        nextSeq++

        val remaining = expectedLength - offset
        val dataSize = minOf(packet.size - CONT_HEADER_SIZE, remaining)
        packet.copyInto(buf, offset, CONT_HEADER_SIZE, CONT_HEADER_SIZE + dataSize)
        offset += dataSize

        return completeIfDone()
    }

    private fun completeIfDone(): ByteArray? {
        if (offset < expectedLength) return null

        // Prepend CMD byte to the reassembled payload
        val result = ByteArray(1 + expectedLength)
        result[0] = expectedCmd
        buffer!!.copyInto(result, 1)
        reset()
        return result
    }
}
