package com.example.phone2pc.model

/**
 * FidoCredential
 *
 * Represents a registered FIDO2 credential stored on this device.
 *
 * @property credentialId   The opaque credential ID bytes sent to the relying party.
 * @property rpId           The relying party ID (e.g., "login.microsoft.com").
 * @property userHandle     Optional opaque user handle from the relying party.
 * @property userName       The name associated with the user account.
 * @property userDisplayName The display name associated with the user account.
 * @property hasHmacSecret  True if this credential has a Keystore-backed HMAC secret.
 * @property createdAtEpoch Unix timestamp (seconds) when this credential was created.
 */
data class FidoCredential(
    val credentialId: ByteArray,
    val rpId: String,
    val keyAlias: String,
    val userHandle: ByteArray?,
    val userName: String?,
    val userDisplayName: String?,
    val hasHmacSecret: Boolean = false,
    val createdAtEpoch: Long
) {
    // ByteArray-aware equals/hashCode
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FidoCredential) return false
        return credentialId.contentEquals(other.credentialId) && rpId == other.rpId
    }

    override fun hashCode(): Int {
        var result = credentialId.contentHashCode()
        result = 31 * result + rpId.hashCode()
        return result
    }
}
