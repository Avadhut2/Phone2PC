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
        val alias = "fido_credential_${java.util.UUID.randomUUID()}"
        
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, KEYSTORE_PROVIDER)
        
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(KEY_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            
        try {
            android.util.Log.i("KeystoreManager", "Attempting StrongBox key generation for: $alias")
            builder.setIsStrongBoxBacked(true)
            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            android.util.Log.w("KeystoreManager", "StrongBox failed or unavailable. Falling back to standard TEE.", e)
            // Rebuild without StrongBox
            val fallbackBuilder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(KEY_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            
            keyPairGenerator.initialize(fallbackBuilder.build())
            keyPairGenerator.generateKeyPair()
        }
        
        return alias
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
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val cert = keyStore.getCertificate(keyAlias)
            ?: throw IllegalStateException("Certificate not found for alias: $keyAlias")
            
        val publicKey = cert.publicKey as? java.security.interfaces.ECPublicKey
            ?: throw IllegalStateException("Public key is not ECDSA")
            
        val x = to32ByteArray(publicKey.w.affineX)
        val y = to32ByteArray(publicKey.w.affineY)
        
        // COSE Key formatting for EC2 secp256r1
        return com.example.phone2pc.ctap.CborEncoder()
            .encodeMapStart(5)
            .encodeUnsignedInt(1) // kty (1)
            .encodeUnsignedInt(2) // EC2 (2)
            .encodeUnsignedInt(3) // alg (3)
            .encodeNegativeInt(-7) // ES256 (-7)
            .encodeNegativeInt(-1) // crv (-1)
            .encodeUnsignedInt(1) // P-256 (1)
            .encodeNegativeInt(-2) // x (-2)
            .encodeByteString(x)
            .encodeNegativeInt(-3) // y (-3)
            .encodeByteString(y)
            .toByteArray()
    }
    
    private fun to32ByteArray(value: java.math.BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
            else -> {
                val padded = ByteArray(32)
                System.arraycopy(bytes, 0, padded, 32 - bytes.size, bytes.size)
                padded
            }
        }
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
