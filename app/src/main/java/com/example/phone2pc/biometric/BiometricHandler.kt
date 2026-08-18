package com.example.phone2pc.biometric

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.Signature

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
class BiometricHandler(private val context: Context) {

    /**
     * Display the biometric prompt to the user. On success, the [signature]
     * inside the [CryptoObject] is unlocked and ready to sign data.
     *
     * @param activity   The foreground FragmentActivity to anchor the prompt to.
     * @param signature  An initialized [Signature] from [KeystoreManager.getSignatureForSigning].
     * @param onSuccess  Called with the authenticated [BiometricPrompt.AuthenticationResult].
     * @param onFailure  Called with a descriptive error message on cancellation or failure.
     */
    fun authenticate(
        activity: FragmentActivity,
        signature: Signature,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onFailure: (String) -> Unit
    ) {
        // TODO(Phase 2): Build BiometricPrompt with CryptoObject(signature),
        //                set title/subtitle/negativeButtonText,
        //                handle AuthenticationCallback.
    }
}
