package com.example.phone2pc.ctap

/**
 * CtapCommand
 *
 * Defines the CTAP2 command byte constants as per FIDO Alliance specification.
 * These are the first byte of every CTAP2 message.
 */
object CtapCommand {
    const val MAKE_CREDENTIAL: Byte = 0x01  // authenticatorMakeCredential
    const val GET_ASSERTION: Byte   = 0x02  // authenticatorGetAssertion
    const val GET_INFO: Byte        = 0x04  // authenticatorGetInfo
    const val CLIENT_PIN: Byte      = 0x06  // authenticatorClientPIN (optional)
    const val RESET: Byte           = 0x07  // authenticatorReset (optional)
}
