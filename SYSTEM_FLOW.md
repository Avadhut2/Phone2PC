# Phone2PC: How It Works (Detailed System Flow)

This document provides a highly detailed breakdown of the complete data flow from the moment Windows attempts to authenticate to the moment the biometric signature is returned. It explores how the different layers of the application work together seamlessly.

## Layer 1: BLE GATT Profile and Advertising
When the app launches, it initiates the `FidoAdvertiser`. 
1. The advertiser broadcasts the standardized FIDO Service UUID `0xFFFD`. This tells nearby devices (like your Windows PC) "I am a FIDO Security Key."
2. The `FidoGattServer` sets up a GATT (Generic Attribute Profile) server with three crucial characteristics under the FIDO Service:
   * **FIDO Control Point:** A write-only characteristic where Windows sends commands (like `MakeCredential` or `GetAssertion`).
   * **FIDO Status:** A notify/read characteristic where the phone sends responses back to Windows.
   * **Service Revision Bitfield:** Indicates the supported FIDO specification versions.
3. **Security Bond:** To prevent connections from spontaneously dropping during authentication, the GATT characteristics are configured with `PERMISSION_WRITE_ENCRYPTED` and `PERMISSION_READ_ENCRYPTED`. This forces Windows and Android to perform OS-level encryption bonding (the pairing PIN prompt you see on your first connection), ensuring that the BLE traffic cannot be intercepted.

## Layer 2: The FIDO BLE Framer
Bluetooth Low Energy packets have a small Maximum Transmission Unit (MTU), often limited to 20 or 512 bytes depending on hardware. A cryptographic payload (especially during registration containing public keys and attestation statements) can exceed 1000 bytes. 
1. **Fragmentation (PC to Phone):** When Windows wants to send a large request, it chunks the data. The first chunk begins with a FIDO command byte (e.g., `0x83` for MSG) and a two-byte payload length. Subsequent chunks begin with a sequence number (`0x00`, `0x01`, etc.).
2. **Reassembly (`BleFramer.kt`):** The framer buffers incoming bytes until the expected payload length is reached. 
3. **Encoding (Phone to PC):** When sending data back, the framer splits the large response into MTU-sized chunks, adding the necessary FIDO framing headers, and sends them one by one through the FIDO Status characteristic using BLE Notifications.

## Layer 3: CBOR Parsing and CTAP Routing
Once a complete FIDO payload is assembled, it is passed to the `CtapRouter`.
1. The first byte of the payload dictates the CTAP2 command (e.g., `0x01` for `MakeCredential`, `0x02` for `GetAssertion`, `0x04` for `GetInfo`).
2. The router strips the command byte and hands the rest to the `CborDecoder`. CBOR (Concise Binary Object Representation) is a highly compact, JSON-like binary format used by FIDO. 
3. The decoder translates the raw bytes into a map of parameters:
   - For `MakeCredential`, it extracts the Relying Party ID (`rpId`), the cryptographically random challenge hash (`clientDataHash`), and user details.
   - For `GetAssertion`, it extracts the `rpId`, `clientDataHash`, and the `allowList` (which credential Windows is requesting).

## Layer 4: Cryptography (Android Keystore)
Once the router understands what Windows wants, it invokes the `KeystoreManager`.
1. **Key Generation (Registration):** The Keystore generates a new ECDSA P-256 (secp256r1) key pair. A critical security feature here is that the private key is generated *inside* the hardware Trusted Execution Environment (TEE or StrongBox). It never exists in the app's memory. It is generated with a unique alias (e.g., `fido_credential_UUID`).
2. **Biometric Binding:** The key is configured with `setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)`. This means Android's OS kernel will mathematically block any attempt to use the key unless a fresh, successful biometric scan occurs.
3. **Public Key Export:** The public key is extracted, encoded into the standard COSE map format, and packaged into the `authData` to send back to Windows.

## Layer 5: The Biometric Gating
1. **Signing Request:** During authentication (`GetAssertion`), the `CtapRouter` prepares the data to sign (`authData` concatenated with the `clientDataHash`).
2. **The CryptoObject:** It asks the `KeystoreManager` for a `Signature` object initialized with the correct private key alias. Because the key is biometric-bound, calling `.sign()` on this object right now would crash the app with a security exception.
3. **The Prompt:** The router passes the initialized `Signature` object to the `MainActivity` through a callback. The `MainActivity` creates a `BiometricPrompt.CryptoObject` containing the signature and displays the Fingerprint/Face prompt to the user.
4. **KeepAlive Heartbeat:** While the prompt is on screen, the user might take a few seconds to scan their finger. To prevent Windows from timing out, the app fires a background coroutine that sends a `0x82` KeepAlive message with status `0x02` (UP_NEEDED) to the PC every 400 milliseconds. 
5. **Authorization:** Once the fingerprint matches, the Android OS unlocks the `Signature` object within the TEE. The `MainActivity` takes the unlocked object, feeds it the `dataToSign`, and retrieves the final ECDSA signature array.

## Layer 6: Finalizing the Flow
1. The signature is packaged back into a CBOR map alongside the `authData`.
2. The map is encoded into bytes.
3. A success byte (`0x00`) is prepended.
4. The `BleFramer` fragments it.
5. The `FidoGattServer` notifies the PC.
6. The PC receives the fragments, reconstructs the signature, verifies it mathematically against the stored public key, and logs the user into the website!
