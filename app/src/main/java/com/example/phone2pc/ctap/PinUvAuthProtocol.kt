package com.example.phone2pc.ctap

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECParameterSpec
import java.security.interfaces.ECPublicKey
import java.security.interfaces.ECPrivateKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.math.BigInteger
import java.security.AlgorithmParameters

/**
 * Implements FIDO CTAP 2.1 pinUvAuthProtocol Version 1.
 * Provides ECDH key agreement, AES-256-CBC encryption, and HMAC-SHA-256.
 */
class PinUvAuthProtocol {

    private val ephemeralKeyPair: KeyPair
    private val keyAgreement: KeyAgreement

    init {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        ephemeralKeyPair = kpg.generateKeyPair()
        
        keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(ephemeralKeyPair.private)
    }

    /**
     * Gets the public key in COSE Key (Map) format.
     */
    fun getPublicKeyCose(): Map<Int, Any> {
        val ecKey = ephemeralKeyPair.public as ECPublicKey
        val w = ecKey.w
        
        var xBytes = w.affineX.toByteArray()
        if (xBytes.size > 32) xBytes = xBytes.copyOfRange(xBytes.size - 32, xBytes.size)
        if (xBytes.size < 32) xBytes = ByteArray(32 - xBytes.size) + xBytes
        
        var yBytes = w.affineY.toByteArray()
        if (yBytes.size > 32) yBytes = yBytes.copyOfRange(yBytes.size - 32, yBytes.size)
        if (yBytes.size < 32) yBytes = ByteArray(32 - yBytes.size) + yBytes

        return mapOf(
            1 to 2,    // kty = EC2
            3 to -7,   // alg = ES256 (not strictly used for ECDH but standard COSE)
            -1 to 1,   // crv = P-256
            -2 to xBytes,
            -3 to yBytes
        )
    }

    /**
     * Parse a COSE Key map into a Java ECPublicKey.
     */
    private fun parseCosePublicKey(coseKey: Map<Any?, Any?>): ECPublicKey {
        val xBytes = (coseKey[-2] ?: coseKey[-2L]) as ByteArray
        val yBytes = (coseKey[-3] ?: coseKey[-3L]) as ByteArray
        
        val x = BigInteger(1, xBytes)
        val y = BigInteger(1, yBytes)
        val point = ECPoint(x, y)
        
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val ecParams = params.getParameterSpec(ECParameterSpec::class.java)
        
        val spec = ECPublicKeySpec(point, ecParams)
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(spec) as ECPublicKey
    }

    /**
     * Performs ECDH and derives the shared secret using SHA-256.
     * CTAP2 pinUvAuthProtocol V1:
     * shared_secret = SHA-256(x-coordinate of ECDH shared point)
     */
    private fun deriveSharedSecret(platformPublicKeyCose: Map<Any?, Any?>): ByteArray {
        val platformKey = parseCosePublicKey(platformPublicKeyCose)
        keyAgreement.doPhase(platformKey, true)
        
        var sharedSecretBytes = keyAgreement.generateSecret()
        if (sharedSecretBytes.size > 32) {
             sharedSecretBytes = sharedSecretBytes.copyOfRange(sharedSecretBytes.size - 32, sharedSecretBytes.size)
        } else if (sharedSecretBytes.size < 32) {
             sharedSecretBytes = ByteArray(32 - sharedSecretBytes.size) + sharedSecretBytes
        }
        
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(sharedSecretBytes)
    }

    /**
     * Exposes the derived shared secret for the client PIN manager.
     */
    fun getSharedSecret(platformPublicKeyCose: Map<Any?, Any?>): ByteArray {
        return deriveSharedSecret(platformPublicKeyCose)
    }

    /**
     * Decrypts the salt using AES-256-CBC.
     */
    fun decrypt(platformPublicKeyCose: Map<Any?, Any?>, ciphertext: ByteArray): ByteArray {
        val sharedSecret = deriveSharedSecret(platformPublicKeyCose)
        val secretKey = SecretKeySpec(sharedSecret, "AES")
        
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        // IV is all zeros for pinUvAuthProtocol V1
        val iv = IvParameterSpec(ByteArray(16))
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
        return cipher.doFinal(ciphertext)
    }

    /**
     * Encrypts the response (the HMACs) using AES-256-CBC.
     */
    fun encrypt(platformPublicKeyCose: Map<Any?, Any?>, plaintext: ByteArray): ByteArray {
        val sharedSecret = deriveSharedSecret(platformPublicKeyCose)
        val secretKey = SecretKeySpec(sharedSecret, "AES")
        
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        val iv = IvParameterSpec(ByteArray(16))
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
        return cipher.doFinal(plaintext)
    }

    /**
     * Generates HMAC-SHA-256 signature using the shared secret.
     */
    fun authenticate(platformPublicKeyCose: Map<Any?, Any?>, message: ByteArray): ByteArray {
        val sharedSecret = deriveSharedSecret(platformPublicKeyCose)
        return authenticateWithToken(sharedSecret, message)
    }
    
    /**
     * Generates HMAC-SHA-256 signature using an explicit token/key.
     */
    fun authenticateWithToken(token: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(token, "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(message)
    }

    /**
     * Verifies the first 16 bytes of the HMAC match the provided signature.
     */
    fun verify(platformPublicKeyCose: Map<Any?, Any?>, message: ByteArray, signature: ByteArray): Boolean {
        val expected = authenticate(platformPublicKeyCose, message)
        val expectedPrefix = expected.copyOfRange(0, 16)
        return MessageDigest.isEqual(expectedPrefix, signature)
    }
    
    /**
     * Verifies the first 16 bytes of the HMAC match using an explicit token.
     */
    fun verifyWithToken(token: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val expected = authenticateWithToken(token, message)
        val expectedPrefix = expected.copyOfRange(0, 16)
        return MessageDigest.isEqual(expectedPrefix, signature)
    }
}
