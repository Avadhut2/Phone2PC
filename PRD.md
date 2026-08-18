# Product Requirements Document (PRD): Phone2PC

## 1. Goal
Develop a production-grade Android application that emulates a FIDO2 / CTAP2 roaming authenticator over Bluetooth Low Energy (BLE). The application must securely gate Windows 10/11 unlocks via hardware-backed cryptographic keys and biometric user verification.

## 2. Target Audience
Enterprise and power users requiring highly secure, passwordless authentication without relying on external USB hardware authenticators.

## 3. Scope & Non-Goals
### In Scope
- Android application acting as a BLE Peripheral.
- Strict implementation of the FIDO BLE protocol and CTAP2 protocol (CBOR).
- Hardware-backed key generation (StrongBox where available).
- Cryptographic gating via Android `BiometricPrompt`.
- Native integration with Windows 10/11 WebAuthn/Security Key architecture.

### Out of Scope / Non-Goals
- Custom Windows Credential Providers or Services.
- Fallback to PIN within the app (rely on Biometrics).
- Cloud synchronization or backup of private keys (strictly hardware-bound).

## 4. Functional Requirements
### 4.1. BLE Communication
*   **FR-1:** The app MUST advertise the FIDO BLE Service UUID (`0xFFFD`).
*   **FR-2:** The app MUST implement FIDO Control Point, Status, and Control Point Length characteristics.
*   **FR-3:** The app MUST handle BLE fragmentation and reassembly precisely according to the FIDO BLE specification.
*   **FR-4:** The app MUST support LE Secure Connections (LESC) during BLE pairing to prevent eavesdropping.

### 4.2. CTAP2 Implementation
*   **FR-5:** The app MUST accurately parse and construct CBOR-encoded CTAP2 payloads.
*   **FR-6:** The app MUST handle `authenticatorMakeCredential` (0x01) to register new keys.
*   **FR-7:** The app MUST handle `authenticatorGetAssertion` (0x02) to authenticate using existing keys.
*   **FR-8:** The app MUST implement the `ES256` (ECDSA P-256) cryptographic algorithm.
*   **FR-9:** The app MUST correctly process the `clientDataHash` and `rpId` (Relying Party ID) to prevent phishing and replay attacks.

### 4.3. Security & Biometrics
*   **FR-10:** Private keys MUST be generated inside the Android Keystore.
*   **FR-11:** If the hardware supports it, keys MUST be stored in the `StrongBox` Keymaster.
*   **FR-12:** Keys MUST be generated with `setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)`.
*   **FR-13:** Cryptographic signing MUST require a fresh `BiometricPrompt` authorization (no timeout windows).
*   **FR-14:** Cryptographic operations MUST use `CryptoObject` to bind the prompt to the Keystore operation.

## 5. Non-Functional Requirements (NFRs)
*   **Security:** Zero logging of sensitive data (challenges, hashes, keys). Memory holding sensitive bytes MUST be explicitly zeroed out when no longer needed.
*   **Reliability:** The BLE GATT server must handle unexpected disconnects cleanly without leaking state or crashing.
*   **Performance:** The biometric prompt should appear within 1 second of the Windows PC sending the `authenticatorGetAssertion` command.

## 6. Success Metrics
- Successful WebAuthn registration and authentication flows on Windows 11.
- No memory leaks or state corruption during repeated BLE disconnects.
- Passes standard Android security linting (e.g., Detekt).
