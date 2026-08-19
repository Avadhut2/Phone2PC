package com.example.phone2pc.biometric

import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.Signature
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * BiometricHandler
 *
 * Orchestrates the Android BiometricPrompt to gate cryptographic operations.
 *
 * CRITICAL SECURITY CONTRACT:
 *   The [Signature] object from [KeystoreManager] MUST be wrapped in a
 *   [BiometricPrompt.CryptoObject] before being passed here. This binding
 *   ensures the Android OS hardware guarantees that the signing operation
 *   can only proceed after the biometric sensor verifies the user.
 *   Do NOT perform signing outside of this class.
 *
 * Phase: 2 — Biometrics & Keystore Integration
 */
class BiometricHandler {

    /**
     * Result of a biometric authentication attempt.
     */
    sealed class AuthResult {
        /** Biometric verified. The [signature] inside CryptoObject is now unlocked. */
        data class Success(val signature: Signature) : AuthResult()
        /** User cancelled or biometric failed. */
        data class Failure(val message: String) : AuthResult()
    }

    /**
     * Display the biometric prompt and suspend until the user authenticates or cancels.
     *
     * @param activity   The foreground FragmentActivity to anchor the prompt to.
     * @param signature  An initialized [Signature] from [KeystoreManager.getSignatureForSigning].
     * @return [AuthResult.Success] with the unlocked Signature, or [AuthResult.Failure].
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        signature: Signature
    ): AuthResult = suspendCoroutine { continuation ->

        val executor = ContextCompat.getMainExecutor(activity)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val authedSignature = result.cryptoObject?.signature
                if (authedSignature != null) {
                    continuation.resume(AuthResult.Success(authedSignature))
                } else {
                    continuation.resume(AuthResult.Failure("CryptoObject signature was null after auth"))
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                continuation.resume(AuthResult.Failure(errString.toString()))
            }

            override fun onAuthenticationFailed() {
                // Called on a single failed attempt (e.g., wrong finger).
                // The prompt stays open — Android handles retries automatically.
                // We do NOT resume the coroutine here.
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Phone2PC Authentication")
            .setSubtitle("Verify your identity to sign in")
            .setNegativeButtonText("Cancel")
            .build()

        val cryptoObject = BiometricPrompt.CryptoObject(signature)
        prompt.authenticate(promptInfo, cryptoObject)
    }
}
