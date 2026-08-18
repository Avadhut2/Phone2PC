package com.example.phone2pc.ctap

/**
 * CtapRouter
 *
 * Receives a fully reassembled CTAP2 message (raw CBOR bytes) from the
 * [com.example.phone2pc.ble.BleFramer], decodes the command byte, and
 * dispatches to the appropriate handler.
 *
 * Supported commands:
 *   0x01 — authenticatorMakeCredential  (registration)
 *   0x02 — authenticatorGetAssertion    (authentication)
 *   0x04 — authenticatorGetInfo         (capability query)
 *
 * Security: All unrecognized command bytes MUST return ERR_INVALID_COMMAND.
 * Parsing errors MUST return ERR_INVALID_CBOR. The router must never panic
 * or throw an unhandled exception on malformed input.
 *
 * Phase: 2 — CTAP2 Protocol Parsing
 */
class CtapRouter {

    /**
     * Process a raw CTAP2 [message] (command byte + CBOR payload) and return
     * the encoded CTAP2 response bytes to be sent back over BLE.
     */
    suspend fun process(message: ByteArray): ByteArray {
        if (message.isEmpty()) {
            return CtapErrorCode.ERR_INVALID_LENGTH.toResponse()
        }

        return when (val cmd = message[0]) {
            CtapCommand.MAKE_CREDENTIAL -> handleMakeCredential(message.drop(1).toByteArray())
            CtapCommand.GET_ASSERTION   -> handleGetAssertion(message.drop(1).toByteArray())
            CtapCommand.GET_INFO        -> handleGetInfo()
            else -> {
                // Unknown command — return standard CTAP2 error.
                CtapErrorCode.ERR_INVALID_COMMAND.toResponse()
            }
        }
    }

    private suspend fun handleMakeCredential(cbor: ByteArray): ByteArray {
        // TODO(Phase 2): Parse CBOR, validate rpId, trigger BiometricHandler,
        //                call KeystoreManager.generateKeyPair(), return attestation object.
        return CtapErrorCode.ERR_NOT_ALLOWED.toResponse()
    }

    private suspend fun handleGetAssertion(cbor: ByteArray): ByteArray {
        // TODO(Phase 2): Parse CBOR, validate rpId + clientDataHash,
        //                trigger BiometricHandler, call KeystoreManager.sign(),
        //                return signed assertion.
        return CtapErrorCode.ERR_NOT_ALLOWED.toResponse()
    }

    private fun handleGetInfo(): ByteArray {
        // TODO(Phase 2): Return CBOR-encoded authenticatorGetInfo response
        //                declaring supported CTAP2 versions and algorithms.
        return CtapErrorCode.ERR_NOT_ALLOWED.toResponse()
    }
}
