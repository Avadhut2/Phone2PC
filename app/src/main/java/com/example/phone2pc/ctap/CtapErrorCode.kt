package com.example.phone2pc.ctap

/**
 * CtapErrorCode
 *
 * Standard CTAP2 error codes as defined by the FIDO Alliance specification.
 * Every error path must return one of these codes so the Windows WebAuthn
 * stack can handle failures gracefully.
 *
 * Usage: `CtapErrorCode.ERR_INVALID_COMMAND.toResponse()`
 */
enum class CtapErrorCode(val code: Byte) {
    ERR_SUCCESS            (0x00),
    ERR_INVALID_COMMAND    (0x01),
    ERR_INVALID_PARAMETER  (0x02),
    ERR_INVALID_LENGTH     (0x03),
    ERR_INVALID_SEQ        (0x04),
    ERR_TIMEOUT            (0x05),
    ERR_CHANNEL_BUSY       (0x06),
    ERR_LOCK_REQUIRED      (0x0A),
    ERR_INVALID_CHANNEL    (0x0B),
    ERR_CBOR_UNEXPECTED_TYPE(0x11),
    ERR_INVALID_CBOR       (0x12),
    ERR_MISSING_PARAMETER  (0x14),
    ERR_LIMIT_EXCEEDED     (0x15),
    ERR_UNSUPPORTED_EXTENSION(0x16),
    ERR_CREDENTIAL_EXCLUDED(0x19),
    ERR_PROCESSING         (0x21),
    ERR_INVALID_CREDENTIAL (0x22),
    ERR_USER_ACTION_PENDING(0x23),
    ERR_OPERATION_PENDING  (0x24),
    ERR_NO_OPERATIONS      (0x25),
    ERR_UNSUPPORTED_ALGORITHM(0x26),
    ERR_OPERATION_DENIED   (0x27),
    ERR_KEY_STORE_FULL     (0x28),
    ERR_NO_OPERATION_PENDING(0x2A),
    ERR_UNSUPPORTED_OPTION (0x2B),
    ERR_INVALID_OPTION     (0x2C),
    ERR_KEEPALIVE_CANCEL   (0x2D),
    ERR_NO_CREDENTIALS     (0x2E),
    ERR_USER_ACTION_TIMEOUT(0x2F),
    ERR_NOT_ALLOWED        (0x30),
    ERR_PIN_INVALID        (0x31),
    ERR_PIN_BLOCKED        (0x32),
    ERR_OTHER              (0x7F);

    /**
     * Encode this error as a CTAP2 response byte array:
     * status byte only (no CBOR payload on errors).
     */
    fun toResponse(): ByteArray = byteArrayOf(code)
}
