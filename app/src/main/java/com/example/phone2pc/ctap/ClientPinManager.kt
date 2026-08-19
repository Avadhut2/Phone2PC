package com.example.phone2pc.ctap

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import com.example.phone2pc.ctap.CborDecoder
import com.example.phone2pc.ctap.CborEncoder

/**
 * Handles the FIDO2 authenticatorClientPin (0x06) command and manages the virtual PIN state.
 */
class ClientPinManager(
    context: Context,
    val pinUvAuthProtocol: PinUvAuthProtocol
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("fido_client_pin", Context.MODE_PRIVATE)

    var currentPinToken: ByteArray? = null
        private set

    fun hasPin(): Boolean {
        return prefs.contains("pin_hash")
    }

    fun clearPin() {
        prefs.edit().clear().apply()
        currentPinToken = null
    }

    fun getRetries(): Int {
        return prefs.getInt("retries", 8)
    }

    private fun setRetries(count: Int) {
        prefs.edit().putInt("retries", count).apply()
    }

    private fun getPinHash(): ByteArray? {
        val b64 = prefs.getString("pin_hash", null) ?: return null
        return Base64.decode(b64, Base64.NO_WRAP)
    }

    private fun setPinHash(hash: ByteArray) {
        val b64 = Base64.encodeToString(hash, Base64.NO_WRAP)
        prefs.edit().putString("pin_hash", b64).putInt("retries", 8).apply()
    }

    private fun sha256Prefix(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data).copyOfRange(0, 16)
    }

    /**
     * Process authenticatorClientPin (0x06) subcommands.
     */
    fun process(params: Map<Int, Any?>): ByteArray {
        val protocol = (params[1] as? Number)?.toInt()
        val subCommand = (params[2] as? Number)?.toInt()

        if (protocol != null && protocol != 1) {
            return CtapErrorCode.ERR_PIN_AUTH_INVALID.toResponse()
        }

        return when (subCommand) {
            1 -> handleGetRetries()
            2 -> handleGetKeyAgreement()
            3 -> handleSetPin(params)
            4 -> handleChangePin(params)
            5 -> handleGetPinToken(params)
            else -> CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        }
    }

    private fun buildSuccessResponse(cbor: ByteArray): ByteArray {
        val response = ByteArray(1 + cbor.size)
        response[0] = CtapErrorCode.ERR_SUCCESS.code
        System.arraycopy(cbor, 0, response, 1, cbor.size)
        return response
    }

    private fun handleGetRetries(): ByteArray {
        val cbor = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(3) // retries key
            .encodeUnsignedInt(getRetries().toLong())
            .toByteArray()
        return buildSuccessResponse(cbor)
    }

    private fun handleGetKeyAgreement(): ByteArray {
        val cbor = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(1) // keyAgreement key
            .encodeMap(pinUvAuthProtocol.getPublicKeyCose())
            .toByteArray()
        return buildSuccessResponse(cbor)
    }

    private fun handleSetPin(params: Map<Int, Any?>): ByteArray {
        if (hasPin()) return CtapErrorCode.ERR_PIN_AUTH_INVALID.toResponse()

        val keyAgreement = params[3] as? Map<Any?, Any?> ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        val pinAuth = params[4] as? ByteArray ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        val newPinEnc = params[5] as? ByteArray ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()

        // Verify pinAuth = HMAC(sharedSecret, newPinEnc)
        if (!pinUvAuthProtocol.verify(keyAgreement, newPinEnc, pinAuth)) {
            return CtapErrorCode.ERR_PIN_AUTH_INVALID.toResponse()
        }

        // Decrypt newPinEnc
        val newPinPadded = pinUvAuthProtocol.decrypt(keyAgreement, newPinEnc)
        // Strip zero padding (last bytes might be 0x00)
        var length = newPinPadded.size
        while (length > 0 && newPinPadded[length - 1] == 0x00.toByte()) {
            length--
        }
        val newPin = newPinPadded.copyOfRange(0, length)
        
        if (newPin.size < 4) return CtapErrorCode.ERR_PIN_POLICY_VIOLATION.toResponse()

        setPinHash(sha256Prefix(newPin))
        val cbor = CborEncoder().encodeMapStart(0).toByteArray() // Empty map = success
        return buildSuccessResponse(cbor)
    }

    private fun handleChangePin(params: Map<Int, Any?>): ByteArray {
        if (!hasPin()) return CtapErrorCode.ERR_PIN_NOT_SET.toResponse()

        val keyAgreement = params[3] as? Map<Any?, Any?> ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        val pinAuth = params[4] as? ByteArray ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        val newPinEnc = params[5] as? ByteArray ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        val pinHashEnc = params[6] as? ByteArray ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()

        val authMessage = newPinEnc + pinHashEnc
        if (!pinUvAuthProtocol.verify(keyAgreement, authMessage, pinAuth)) {
            return CtapErrorCode.ERR_PIN_AUTH_INVALID.toResponse()
        }

        val storedPinHash = getPinHash() ?: return CtapErrorCode.ERR_PIN_NOT_SET.toResponse()
        val decryptedPinHash = pinUvAuthProtocol.decrypt(keyAgreement, pinHashEnc).copyOfRange(0, 16)

        var retries = getRetries()
        if (retries <= 0) return CtapErrorCode.ERR_PIN_BLOCKED.toResponse()

        if (!MessageDigest.isEqual(storedPinHash, decryptedPinHash)) {
            retries--
            setRetries(retries)
            if (retries == 0) return CtapErrorCode.ERR_PIN_BLOCKED.toResponse()
            return CtapErrorCode.ERR_PIN_INVALID.toResponse()
        }

        val newPinPadded = pinUvAuthProtocol.decrypt(keyAgreement, newPinEnc)
        var length = newPinPadded.size
        while (length > 0 && newPinPadded[length - 1] == 0x00.toByte()) {
            length--
        }
        val newPin = newPinPadded.copyOfRange(0, length)
        
        if (newPin.size < 4) return CtapErrorCode.ERR_PIN_POLICY_VIOLATION.toResponse()

        setPinHash(sha256Prefix(newPin))
        val cbor = CborEncoder().encodeMapStart(0).toByteArray()
        return buildSuccessResponse(cbor)
    }

    private fun handleGetPinToken(params: Map<Int, Any?>): ByteArray {
        if (!hasPin()) return CtapErrorCode.ERR_PIN_NOT_SET.toResponse()

        val keyAgreement = params[3] as? Map<Any?, Any?> ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()
        val pinHashEnc = params[6] as? ByteArray ?: return CtapErrorCode.ERR_INVALID_PARAMETER.toResponse()

        val storedPinHash = getPinHash() ?: return CtapErrorCode.ERR_PIN_NOT_SET.toResponse()
        val decryptedPinHash = pinUvAuthProtocol.decrypt(keyAgreement, pinHashEnc).copyOfRange(0, 16)

        var retries = getRetries()
        if (retries <= 0) return CtapErrorCode.ERR_PIN_BLOCKED.toResponse()

        if (!MessageDigest.isEqual(storedPinHash, decryptedPinHash)) {
            retries--
            setRetries(retries)
            if (retries == 0) return CtapErrorCode.ERR_PIN_BLOCKED.toResponse()
            return CtapErrorCode.ERR_PIN_INVALID.toResponse()
        }

        // Success, reset retries
        setRetries(8)

        // CTAP 2.0 (protocol 1): return an encrypted pinToken (16 bytes). 
        // We generate a random one and keep it in memory for the session.
        val token = ByteArray(16)
        SecureRandom().nextBytes(token)
        currentPinToken = token

        val encryptedToken = pinUvAuthProtocol.encrypt(keyAgreement, token)

        val cbor = CborEncoder()
            .encodeMapStart(1)
            .encodeUnsignedInt(2) // pinUvAuthToken key
            .encodeByteString(encryptedToken)
            .toByteArray()
        return buildSuccessResponse(cbor)
    }
}
