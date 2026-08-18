package com.example.phone2pc.model

/**
 * RelyingParty
 *
 * Represents a FIDO2 relying party (the Windows machine / authentication service)
 * that has registered credentials on this device.
 *
 * @property id          The RP ID as declared in the WebAuthn ceremony (e.g., "login.microsoft.com").
 * @property displayName Human-readable name shown in the biometric prompt.
 */
data class RelyingParty(
    val id: String,
    val displayName: String
)
