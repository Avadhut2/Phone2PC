package com.example.phone2pc.crypto

import android.content.Context

/**
 * CredentialStore
 *
 * Persistent mapping of FIDO credential IDs to their Android Keystore key aliases.
 * Stored in encrypted SharedPreferences (EncryptedSharedPreferences).
 *
 * This is NOT a cloud store. All data is strictly local to the device.
 *
 * Security: The credential ID is opaque to the relying party. Internally it maps
 * to the Keystore alias where the private key lives. No private key material is
 * ever stored here.
 *
 * Phase: 2 — Cryptography & Keystore
 */
class CredentialStore(private val context: Context) {

    /**
     * Persist a mapping from [credentialId] to [keyAlias] for the given [rpId].
     */
    fun save(rpId: String, credentialId: ByteArray, keyAlias: String) {
        // TODO(Phase 2): Store in EncryptedSharedPreferences keyed by rpId+credentialId.
    }

    /**
     * Retrieve the Keystore key alias for the given [rpId] and [credentialId].
     * Returns null if no credential is found.
     */
    fun getKeyAlias(rpId: String, credentialId: ByteArray): String? {
        // TODO(Phase 2): Look up EncryptedSharedPreferences.
        return null
    }

    /**
     * Remove the credential mapping for [credentialId] under [rpId].
     * Note: also call [KeystoreManager.deleteKey] to purge the actual key.
     */
    fun delete(rpId: String, credentialId: ByteArray) {
        // TODO(Phase 2): Remove from EncryptedSharedPreferences.
    }
}
