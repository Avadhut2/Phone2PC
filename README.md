# Phone2PC

Phone2PC transforms your Android smartphone into a secure, hardware-backed biometric FIDO2 authenticator for your Windows PC over Bluetooth Low Energy (BLE).

## Overview

Instead of entering a password or using a dedicated USB security key, Phone2PC leverages your phone's built-in secure enclave (Android Keystore) and biometric sensors (Fingerprint/Face Unlock). By emulating the standard **CTAP2 (Client to Authenticator Protocol)** over BLE, Phone2PC works natively with Windows 10 and 11. No custom drivers or desktop software are required on the PC.

## Features Completed
- **BLE FIDO2 Emulation:** Implements GATT profiles (`FIDO_SERVICE_UUID`, `FIDO_CONTROL_POINT`, etc.) to perfectly mimic a physical security key.
- **CTAP2 Parsing:** Parses CBOR requests from Windows and returns perfectly structured CBOR responses for `MakeCredential` (registration) and `GetAssertion` (authentication).
- **Hardware-Backed Cryptography:** Keys are generated using Android's StrongBox (where available) and never leave the TEE (Trusted Execution Environment).
- **Biometric Gating:** All signature operations require successful Android `BiometricPrompt` authentication.
- **KeepAlive Heartbeats:** Prevents the PC from timing out during biometric scans by utilizing the CTAP `0x82` KeepAlive protocol.
- **Passkey Web Support:** Fully supports WebAuthn authentication on sites like `webauthn.io`, GitHub, and Google.

## Strict Security Philosophy
This project strictly adheres to production-grade security standards:
* **Hardware-Backed Exclusivity:** Cryptographic keys are confined to the Android hardware-backed Keystore. They cannot be extracted or exported.
* **Biometric Gating:** Cryptographic signing operations are unconditionally gated by Android's OS-level Biometric integration.
* **Zero Logging:** Secrets, challenges, and private keys are never logged or written to disk.
* **Native Integration:** By relying on native Windows FIDO2 integration, we avoid tampering with the Windows Local Security Authority (LSA) or storing wrapped passwords.

## How to Build and Test

1. Clone the repository and open it in **Android Studio**.
2. Run the app on a physical Android device (BLE emulation is generally not supported on emulators).
3. Ensure Bluetooth is enabled on both your phone and Windows PC.
4. Open the **Phone2PC** app. It will automatically request BLE permissions and start advertising as a FIDO Security Key.
5. On your Windows PC, ensure Bluetooth is turned on.
6. Open your PC web browser (Edge/Chrome) and navigate to a WebAuthn test site (like [webauthn.io](https://webauthn.io)).
7. Enter a username and click **Register**.
8. Windows Hello will prompt you to use your security key. Select your phone from the Bluetooth devices list, and a pairing prompt will appear on both your phone and PC.
9. Match the PINs to establish an encrypted Bluetooth bond.
10. The phone will display a Biometric Prompt. Scan your fingerprint to authorize the registration!
11. You can now use the **Authenticate** button on the website to log in using your phone's fingerprint sensor.

## Documentation
* [Product Requirements Document (PRD)](PRD.md)
* [Architecture Overview](ARCHITCTURE.md)
* [Agent Rules (Coding Standards)](AGENTS.md)
