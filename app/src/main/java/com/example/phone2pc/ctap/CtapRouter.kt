package com.example.phone2pc.ctap

import com.example.phone2pc.crypto.KeystoreManager
import com.example.phone2pc.model.CredentialStore
import com.example.phone2pc.model.FidoCredential
import java.security.SecureRandom
import java.security.Signature

/**
 * CtapRouter
 *
 * Receives a fully reassembled CTAP2 message (raw CBOR bytes) from the
 * [com.example.phone2pc.ble.BleFramer], decodes the command byte, and
 * dispatches to the appropriate handler.
 *
 * Supported commands:
 *   0x01 — authenticatorMakeCredential  (registration)
 *   0x02 — authenticatorGetAssertion    (authentication)
 *   0x04 — authenticatorGetInfo         (capability query)
 *
 * Security: All unrecognized command bytes MUST return ERR_INVALID_COMMAND.
 * Parsing errors MUST return ERR_INVALID_CBOR. The router must never panic
 * or throw an unhandled exception on malformed input.
 *
 * Phase: 2 — CTAP2 Protocol Parsing
 */
class CtapRouter(
    private val keystoreManager: KeystoreManager = KeystoreManager(),
    private val credentialStore: CredentialStore? = null,
    /**
     * Biometric authenticator callback. Receives an initialized [Signature],
     * must return the same Signature after user verification (via BiometricPrompt),
     * or null if the user cancelled.
     */
    private val authenticateBiometric: (suspend (Signature) -> Signature?)? = null
) {
    companion object {
        private val AAGUID = ByteArray(16) // All zeros — no formal attestation
    }

    /**
     * Process a raw CTAP2 [message] (command byte + CBOR payload) and return
     * the encoded CTAP2 response bytes to be sent back over BLE.
     */
    suspend fun process(message: ByteArray): ByteArray {
        if (message.isEmpty()) {
            return CtapErrorCode.ERR_INVALID_LENGTH.toResponse()
        }

        return when (message[0]) {
            CtapCommand.MAKE_CREDENTIAL -> handleMakeCredential(message.copyOfRange(1, message.size))
            CtapCommand.GET_ASSERTION   -> handleGetAssertion(message.copyOfRange(1, message.size))
            CtapCommand.GET_INFO        -> handleGetInfo()
            else -> CtapErrorCode.ERR_INVALID_COMMAND.toResponse()
        }
    }

    /**
     * authenticatorMakeCredential (0x01)
     *
     * CTAP2 request CBOR map keys:
     *   1: clientDataHash (byte string, 32 bytes)
     *   2: rp             (map: {"id": string, "name": string})
     *   3: user           (map: {"id": byte string, "name": string, "displayName": string})
     *   4: pubKeyCredParams (array of maps: {"type": "public-key", "alg": int})
     */
    private suspend fun handleMakeCredential(cbor: ByteArray): ByteArray {
        // --- Parse request ---
        val params: Map<Int, Any?>
        try {
            params = CborDecoder(cbor).readIntKeyMap()
        } catch (e: Exception) {
            return CtapErrorCode.ERR_INVALID_CBOR.toResponse()
        }

        // 1: clientDataHash (required, 32 bytes)
        val clientDataHash = params[1] as? ByteArray
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()
        if (clientDataHash.size != 32) {
            return CtapErrorCode.ERR_INVALID_LENGTH.toResponse()
        }

        // 2: rp (required, map with "id")
        @Suppress("UNCHECKED_CAST")
        val rpMap = params[2] as? Map<Any?, Any?>
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()
        val rpId = rpMap["id"] as? String
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()

        // 3: user (required, map with "id")
        @Suppress("UNCHECKED_CAST")
        val userMap = params[3] as? Map<Any?, Any?>
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()
        val userId = userMap["id"] as? ByteArray
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()

        // 4: pubKeyCredParams (required, must contain ES256 = alg -7)
        @Suppress("UNCHECKED_CAST")
        val pubKeyCredParams = params[4] as? List<Any?>
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()

        val supportsEs256 = pubKeyCredParams.any { item ->
            val map = item as? Map<*, *> ?: return@any false
            val alg = map["alg"]
            // CBOR integers decode as Long
            alg == -7L
        }
        if (!supportsEs256) {
            return CtapErrorCode.ERR_UNSUPPORTED_ALGORITHM.toResponse()
        }

        // --- Generate credential ---
        val credentialId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyAlias: String
        try {
            keyAlias = keystoreManager.generateKeyPair(rpId)
        } catch (e: Exception) {
            return CtapErrorCode.ERR_OTHER.toResponse()
        }

        // --- Biometric authentication (if handler is wired) ---
        if (authenticateBiometric != null) {
            try {
                val sig = keystoreManager.getSignatureForSigning(keyAlias)
                val authedSig = authenticateBiometric.invoke(sig)
                    ?: return CtapErrorCode.ERR_OPERATION_DENIED.toResponse()
                // Signature authorized but not used here — MakeCredential uses self-attestation
            } catch (e: Exception) {
                return CtapErrorCode.ERR_OTHER.toResponse()
            }
        }

        // --- Build authenticator data ---
        val cosePublicKey: ByteArray
        try {
            cosePublicKey = keystoreManager.getPublicKeyCose(keyAlias)
        } catch (e: Exception) {
            return CtapErrorCode.ERR_OTHER.toResponse()
        }

        val authData = AuthenticatorData.buildForRegistration(
            rpId = rpId,
            signCount = 0,
            aaguid = AAGUID,
            credentialId = credentialId,
            cosePublicKey = cosePublicKey
        )

        // --- Build CTAP2 response: {1: fmt, 2: authData, 3: attStmt} ---
        val responseCbor = CborEncoder()
            .encodeMapStart(3)
            .encodeUnsignedInt(1)
            .encodeTextString("none")
            .encodeUnsignedInt(2)
            .encodeByteString(authData)
            .encodeUnsignedInt(3)
            .encodeMapStart(0) // Empty attStmt for "none"
            .toByteArray()

        // --- Persist credential mapping ---
        credentialStore?.save(
            FidoCredential(
                credentialId = credentialId,
                rpId = rpId,
                keyAlias = keyAlias,
                userHandle = userId.copyOf(), // Copy before clearing
                createdAtEpoch = System.currentTimeMillis() / 1000
            )
        )

        // Clear sensitive data from memory
        clientDataHash.fill(0)
        userId.fill(0)

        return buildSuccessResponse(responseCbor)
    }

    /**
     * authenticatorGetAssertion (0x02)
     *
     * CTAP2 request CBOR map keys:
     *   1: rpId            (text string)
     *   2: clientDataHash  (byte string, 32 bytes)
     *   3: allowList        (array of credential descriptors, optional)
     */
    private suspend fun handleGetAssertion(cbor: ByteArray): ByteArray {
        // --- Parse request ---
        val params: Map<Int, Any?>
        try {
            params = CborDecoder(cbor).readIntKeyMap()
        } catch (e: Exception) {
            return CtapErrorCode.ERR_INVALID_CBOR.toResponse()
        }

        // 1: rpId (required)
        val rpId = params[1] as? String
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()

        // 2: clientDataHash (required, 32 bytes)
        val clientDataHash = params[2] as? ByteArray
            ?: return CtapErrorCode.ERR_MISSING_PARAMETER.toResponse()
        if (clientDataHash.size != 32) {
            return CtapErrorCode.ERR_INVALID_LENGTH.toResponse()
        }

        // --- Look up credential ---
        val store = credentialStore
            ?: return CtapErrorCode.ERR_OTHER.toResponse()

        var credentials = store.findByRpId(rpId)
        if (credentials.isEmpty()) {
            return CtapErrorCode.ERR_NO_CREDENTIALS.toResponse()
        }

        // 3: allowList (optional, array of PublicKeyCredentialDescriptor)
        @Suppress("UNCHECKED_CAST")
        val allowList = params[3] as? List<Map<Any?, Any?>>
        if (allowList != null) {
            val allowedIds = allowList.mapNotNull { it["id"] as? ByteArray }
            credentials = credentials.filter { cred ->
                allowedIds.any { allowedId -> allowedId.contentEquals(cred.credentialId) }
            }
            if (credentials.isEmpty()) {
                return CtapErrorCode.ERR_NO_CREDENTIALS.toResponse()
            }
        }

        val credential = credentials.first()

        // --- Biometric authentication + signing ---
        val signature: ByteArray
        val authData = AuthenticatorData.buildForAssertion(
            rpId = rpId,
            signCount = 1, // TODO: Track and increment per credential
            userPresent = true,
            userVerified = true
        )

        // Data to sign = authData || clientDataHash
        val dataToSign = authData + clientDataHash

        if (authenticateBiometric != null) {
            try {
                val sig = keystoreManager.getSignatureForSigning(credential.keyAlias)
                val authedSig = authenticateBiometric.invoke(sig)
                    ?: return CtapErrorCode.ERR_OPERATION_DENIED.toResponse()
                authedSig.update(dataToSign)
                signature = authedSig.sign()
            } catch (e: Exception) {
                return CtapErrorCode.ERR_OTHER.toResponse()
            }
        } else {
            return CtapErrorCode.ERR_OTHER.toResponse()
        }

        // --- Build response CBOR ---
        val responseCbor = CborEncoder()
            .encodeMapStart(3)
            // 1: credential descriptor
            .encodeUnsignedInt(1)
            .encodeMapStart(2)
            .encodeTextString("type")
            .encodeTextString("public-key")
            .encodeTextString("id")
            .encodeByteString(credential.credentialId)
            // 2: authData
            .encodeUnsignedInt(2)
            .encodeByteString(authData)
            // 3: signature
            .encodeUnsignedInt(3)
            .encodeByteString(signature)
            .toByteArray()

        // Clear sensitive data
        clientDataHash.fill(0)
        dataToSign.fill(0)

        return buildSuccessResponse(responseCbor)
    }

    private fun handleGetInfo(): ByteArray {
        val cbor = CborEncoder()
            .encodeMapStart(4)
            // 0x01: versions
            .encodeUnsignedInt(1)
            .encodeArrayStart(1)
            .encodeTextString("FIDO_2_0")
            // 0x03: aaguid
            .encodeUnsignedInt(3)
            .encodeByteString(AAGUID)
            // 0x04: options
            .encodeUnsignedInt(4)
            .encodeMapStart(3)
            .encodeTextString("rk")
            .encodeBoolean(true)
            .encodeTextString("up")
            .encodeBoolean(true)
            .encodeTextString("uv")
            .encodeBoolean(true)
            // 0x05: maxMsgSize
            .encodeUnsignedInt(5)
            .encodeUnsignedInt(1024)
            .toByteArray()

        return buildSuccessResponse(cbor)
    }

    private fun buildSuccessResponse(cbor: ByteArray): ByteArray {
        val response = ByteArray(1 + cbor.size)
        response[0] = CtapErrorCode.ERR_SUCCESS.code
        System.arraycopy(cbor, 0, response, 1, cbor.size)
        return response
    }
}
