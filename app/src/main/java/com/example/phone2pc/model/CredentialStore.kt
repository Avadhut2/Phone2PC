package com.example.phone2pc.model

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64

/**
 * CredentialStore
 *
 * Persists the mapping between FIDO credential IDs and their associated
 * Keystore aliases and relying party IDs. The actual private keys live
 * inside the Android Keystore hardware — this store only holds the
 * non-secret metadata needed to locate them.
 *
 * Storage format per entry:
 *   Key:   Base64(credentialId)
 *   Value: rpId\nkeyAlias\nBase64(userHandle)\nsignCount
 *
 * Phase: 2 — CTAP2 Credential Management
 */
class CredentialStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "fido_credentials"
        private const val FIELD_SEPARATOR = "\n"
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Save a credential after successful MakeCredential. */
    fun save(credential: FidoCredential) {
        val key = Base64.encodeToString(credential.credentialId, Base64.NO_WRAP)
        val userHandleB64 = credential.userHandle?.let {
            Base64.encodeToString(it, Base64.NO_WRAP)
        } ?: ""

        val value = listOf(
            credential.rpId,
            credential.keyAlias,
            userHandleB64,
            credential.createdAtEpoch.toString()
        ).joinToString(FIELD_SEPARATOR)

        prefs.edit().putString(key, value).apply()
    }

    /** Find all credentials for a given relying party. */
    fun findByRpId(rpId: String): List<FidoCredential> {
        return prefs.all.mapNotNull { (key, value) ->
            val credential = deserialize(key, value as? String ?: return@mapNotNull null)
            if (credential?.rpId == rpId) credential else null
        }
    }

    /** Find a specific credential by its ID. */
    fun findByCredentialId(credentialId: ByteArray): FidoCredential? {
        val key = Base64.encodeToString(credentialId, Base64.NO_WRAP)
        val value = prefs.getString(key, null) ?: return null
        return deserialize(key, value)
    }

    /** Delete a credential. */
    fun delete(credentialId: ByteArray) {
        val key = Base64.encodeToString(credentialId, Base64.NO_WRAP)
        prefs.edit().remove(key).apply()
    }

    /** Delete all stored credentials. */
    fun clear() {
        prefs.edit().clear().apply()
    }

    private fun deserialize(keyB64: String, value: String): FidoCredential? {
        val fields = value.split(FIELD_SEPARATOR)
        if (fields.size < 4) return null

        val credentialId = Base64.decode(keyB64, Base64.NO_WRAP)
        val rpId = fields[0]
        val keyAlias = fields[1]
        val userHandle = if (fields[2].isNotEmpty()) {
            Base64.decode(fields[2], Base64.NO_WRAP)
        } else null
        val createdAtEpoch = fields[3].toLongOrNull() ?: return null

        return FidoCredential(
            credentialId = credentialId,
            rpId = rpId,
            keyAlias = keyAlias,
            userHandle = userHandle,
            createdAtEpoch = createdAtEpoch
        )
    }
}
