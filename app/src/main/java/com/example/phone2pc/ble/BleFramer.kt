package com.example.phone2pc.ble

/**
 * BleFramer
 *
 * Implements the FIDO BLE fragmentation and reassembly protocol as defined by
 * the FIDO Alliance CTAP2 BLE specification, Section 3.
 *
 * BLE has a limited MTU (typically 20–512 bytes). FIDO messages can be larger,
 * so they are split into:
 *   - Initialization packet: CMD | HLEN | LLEN | DATA[0..n]
 *   - Continuation packet:   SEQ | DATA[n+1..]
 *
 * Security: Malformed or out-of-sequence frames must be rejected immediately
 * and result in a CTAP2 ERR_INVALID_SEQ or ERR_INVALID_LENGTH error response.
 * No partial state should be retained after a framing error.
 *
 * Phase: 1 — BLE FIDO2 GATT Service
 */
class BleFramer {

    /**
     * Fragment a complete FIDO message [data] into BLE packets no larger than [mtu] bytes.
     *
     * @param cmd  The FIDO command byte (e.g., 0x83 for MSG).
     * @param data The full serialized CTAP2 payload.
     * @param mtu  The negotiated BLE MTU size.
     * @return     An ordered list of byte arrays ready to be sent sequentially.
     */
    fun fragment(cmd: Byte, data: ByteArray, mtu: Int): List<ByteArray> {
        // TODO(Phase 1): Implement FIDO BLE fragmentation per spec Section 3.
        return emptyList()
    }

    /**
     * Accumulate an incoming BLE [packet] and return the complete reassembled
     * FIDO message payload once all fragments have been received, or null if
     * more packets are still expected.
     *
     * @throws IllegalArgumentException if the packet is malformed or out of sequence.
     */
    fun accumulate(packet: ByteArray): ByteArray? {
        // TODO(Phase 1): Implement FIDO BLE reassembly per spec Section 3.
        return null
    }

    /** Reset internal reassembly state (call on disconnect or error). */
    fun reset() {
        // TODO(Phase 1): Clear any buffered partial frames.
    }
}
