# Phone2PC

Phone2PC transforms your Android smartphone into a secure, hardware-backed biometric FIDO2 authenticator for your Windows PC over Bluetooth Low Energy (BLE).

## Overview

Instead of entering a password or using a dedicated USB security key, Phone2PC leverages your phone's built-in secure enclave (Android Keystore) and biometric sensors (Fingerprint/Face Unlock). By emulating the standard **CTAP2 (Client to Authenticator Protocol)** over BLE, Phone2PC works natively with Windows 10 and 11. No custom drivers or desktop software are required on the PC.

## Strict Security Philosophy
This project strictly adheres to production-grade security standards:
* **Hardware-Backed Exclusivity:** Cryptographic keys are confined to the Android hardware-backed Keystore (preferably StrongBox). They cannot be extracted.
* **Biometric Gating:** Cryptographic signing operations are unconditionally gated by Android's `BiometricPrompt`.
* **Zero Logging:** Secrets, challenges, and private keys are never logged or written to disk.
* **Native Integration:** By relying on native Windows FIDO2 integration, we avoid tampering with the Windows Local Security Authority (LSA) or storing wrapped passwords.

## Getting Started

*(Development in progress. Instructions for building the Android app will be placed here.)*

To pair with Windows:
1. Open the Phone2PC app on your Android device and enable BLE advertising.
2. On your Windows PC, navigate to **Settings > Accounts > Sign-in options > Security Key**.
3. Select "Manage" and follow the prompts to add a new Bluetooth security key.

## Documentation
* [Product Requirements Document (PRD)](PRD.md)
* [Architecture Overview](ARCHITCTURE.md)
* [Agent Rules (Coding Standards)](AGENTS.md)
