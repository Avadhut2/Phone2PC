package com.example.phone2pc.ctap

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * AuthenticatorData
 *
 * Builds the binary authenticatorData structure per WebAuthn §6.1:
 *
 *   rpIdHash (32 bytes) || flags (1 byte) || signCount (4 bytes, big-endian)
 *   || [attestedCredentialData] || [extensions]
 *
 * attestedCredentialData (only present during MakeCredential):
 *   aaguid (16 bytes) || credentialIdLength (2 bytes, big-endian)
 *   || credentialId (L bytes) || credentialPublicKey (COSE-encoded)
 *
 * Phase: 2 — CTAP2 Protocol
 */
object AuthenticatorData {

    // Flags bits per WebAuthn spec
    const val FLAG_UP: Byte = 0x01          // User Present
    const val FLAG_UV: Byte = 0x04          // User Verified
    const val FLAG_AT: Byte = 0x40          // Attested Credential Data included
    // FLAG_ED = 0x80 (Extensions — not used yet)

    /**
     * Build authenticatorData for an assertion (GetAssertion).
     * No attested credential data — just rpIdHash + flags + signCount.
     */
    fun buildForAssertion(
        rpId: String,
        signCount: Int,
        userPresent: Boolean = true,
        userVerified: Boolean = true
    ): ByteArray {
        val out = ByteArrayOutputStream(37)
        out.write(hashRpId(rpId))
        out.write(buildFlags(userPresent, userVerified, attestedData = false).toInt())
        out.write(intToBigEndian(signCount))
        return out.toByteArray()
    }

    /**
     * Build authenticatorData for a registration (MakeCredential).
     * Includes attested credential data with the public key.
     *
     * @param rpId              Relying party identifier.
     * @param signCount         Signature counter (starts at 0 for new credentials).
     * @param aaguid            16-byte Authenticator Attestation GUID.
     * @param credentialId      Opaque credential identifier bytes.
     * @param cosePublicKey     COSE-encoded public key bytes.
     */
    fun buildForRegistration(
        rpId: String,
        signCount: Int,
        aaguid: ByteArray,
        credentialId: ByteArray,
        cosePublicKey: ByteArray
    ): ByteArray {
        require(aaguid.size == 16) { "AAGUID must be 16 bytes" }

        val out = ByteArrayOutputStream()
        out.write(hashRpId(rpId))
        out.write(buildFlags(userPresent = true, userVerified = true, attestedData = true).toInt())
        out.write(intToBigEndian(signCount))

        // Attested credential data
        out.write(aaguid)
        out.write(shortToBigEndian(credentialId.size))
        out.write(credentialId)
        out.write(cosePublicKey)

        return out.toByteArray()
    }

    /** SHA-256 hash of the rpId string, as required by WebAuthn. */
    fun hashRpId(rpId: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
    }

    private fun buildFlags(userPresent: Boolean, userVerified: Boolean, attestedData: Boolean): Byte {
        var flags = 0
        if (userPresent) flags = flags or FLAG_UP.toInt()
        if (userVerified) flags = flags or FLAG_UV.toInt()
        if (attestedData) flags = flags or FLAG_AT.toInt()
        return flags.toByte()
    }

    private fun intToBigEndian(value: Int): ByteArray = byteArrayOf(
        (value shr 24 and 0xFF).toByte(),
        (value shr 16 and 0xFF).toByte(),
        (value shr 8 and 0xFF).toByte(),
        (value and 0xFF).toByte()
    )

    private fun shortToBigEndian(value: Int): ByteArray = byteArrayOf(
        (value shr 8 and 0xFF).toByte(),
        (value and 0xFF).toByte()
    )
}
