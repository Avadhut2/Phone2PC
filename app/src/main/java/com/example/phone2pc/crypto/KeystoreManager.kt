package com.example.phone2pc.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

/**
 * KeystoreManager
 *
 * The cryptographic heart of Phone2PC. All key generation and signing
 * operations are delegated to the Android Keystore hardware-backed TEE
 * (or StrongBox where available).
 *
 * Security invariants (MUST NEVER be violated):
 *   - Private keys are generated INSIDE the Keystore. They never exist in JVM heap.
 *   - [setUserAuthenticationRequired(true)] enforces biometric gating at the OS level.
 *   - [setInvalidatedByBiometricEnrollment(true)] destroys keys if new biometrics are added.
 *   - Signing is only possible via a [Signature] wrapped in a [BiometricPrompt.CryptoObject].
 *
 * Phase: 2 — Cryptography & Keystore
 */
class KeystoreManager {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        private const val KEY_CURVE = "secp256r1"  // NIST P-256, required by CTAP2 ES256
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }

    /**
     * Generate a new ECDSA P-256 key pair inside the Android Keystore for the given [rpId].
     * Requires biometric authentication before the private key can be used.
     *
     * @param rpId The relying party ID (e.g., "login.microsoft.com").
     * @return     The key alias used to reference this credential.
     */
    fun generateKeyPair(rpId: String): String {
        // TODO(Phase 2): Build KeyGenParameterSpec with:
        //   - setUserAuthenticationRequired(true)
        //   - setInvalidatedByBiometricEnrollment(true)
        //   - setIsStrongBoxBacked(true) with fallback to TEE
        //   - ECGenParameterSpec("secp256r1")
        //   - KeyProperties.PURPOSE_SIGN
        return rpId  // placeholder — returns alias
    }

    /**
     * Retrieve an initialized [Signature] object for the credential identified
     * by [keyAlias]. This Signature must be wrapped in a [BiometricPrompt.CryptoObject]
     * before any signing can take place.
     *
     * @throws java.security.KeyStoreException if the key alias does not exist.
     */
    fun getSignatureForSigning(keyAlias: String): Signature {
        // TODO(Phase 2): Load key from AndroidKeyStore, init Signature for signing.
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(keyAlias, null)
        return Signature.getInstance(SIGNATURE_ALGORITHM).apply {
            initSign(privateKey as java.security.PrivateKey)
        }
    }

    /**
     * Return the raw public key bytes (COSE-encoded) for the given [keyAlias]
     * so they can be included in the attestation object sent to Windows.
     */
    fun getPublicKeyCose(keyAlias: String): ByteArray {
        // TODO(Phase 2): Load public key from Keystore and encode as COSE Key (RFC 8152).
        return ByteArray(0)
    }

    /**
     * Delete the key pair for [keyAlias] from the Keystore.
     * Called during credential revocation or device reset.
     */
    fun deleteKey(keyAlias: String) {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
    }
}
