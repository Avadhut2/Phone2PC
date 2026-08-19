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
 *   Value: rpId\nkeyAlias\nBase64(userHandle)\nsignCount\nBase64(userName)\nBase64(userDisplayName)
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

        val userNameB64 = credential.userName?.let {
            Base64.encodeToString(it.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        } ?: ""
        
        val userDisplayNameB64 = credential.userDisplayName?.let {
            Base64.encodeToString(it.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        } ?: ""

        val value = listOf(
            credential.rpId,
            credential.keyAlias,
            userHandleB64,
            credential.createdAtEpoch.toString(),
            userNameB64,
            userDisplayNameB64,
            credential.hasHmacSecret.toString()
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

    private fun deserialize(key: String, value: String): FidoCredential? {
        val parts = value.split(FIELD_SEPARATOR)
        if (parts.size < 4) return null
        
        val credentialId = try { Base64.decode(key, Base64.NO_WRAP) } catch (e: Exception) { return null }
        val rpId = parts[0]
        val keyAlias = parts[1]
        val userHandle = if (parts[2].isNotEmpty()) {
            try { Base64.decode(parts[2], Base64.NO_WRAP) } catch (e: Exception) { null }
        } else null
        val createdAt = parts[3].toLongOrNull() ?: 0L
        
        var userName: String? = null
        var userDisplayName: String? = null
        var hasHmacSecret = false
        
        if (parts.size >= 6) {
            userName = if (parts[4].isNotEmpty()) {
                try { String(Base64.decode(parts[4], Base64.NO_WRAP), Charsets.UTF_8) } catch (e: Exception) { null }
            } else null
            
            userDisplayName = if (parts[5].isNotEmpty()) {
                try { String(Base64.decode(parts[5], Base64.NO_WRAP), Charsets.UTF_8) } catch (e: Exception) { null }
            } else null
        }
        
        if (parts.size >= 7) {
            hasHmacSecret = parts[6].toBoolean()
        }

        return FidoCredential(
            credentialId = credentialId, 
            rpId = rpId, 
            keyAlias = keyAlias, 
            userHandle = userHandle,
            userName = userName,
            userDisplayName = userDisplayName,
            hasHmacSecret = hasHmacSecret,
            createdAtEpoch = createdAt
        )
    }
}
