# Agent Customizations & Rules for Phone2PC

This file contains strict rules for AI coding assistants and developers working on this repository. Adherence is mandatory to maintain production-grade security and code quality.

## 1. Architecture & Protocol Constraints
- **Strict FIDO2 / CTAP2:** This project is a FIDO2 CTAP2 BLE roaming authenticator. You must adhere strictly to the FIDO Alliance specifications.
- **NO WINDOWS CODE:** The PC side relies entirely on native Windows Hello functionality. Do not write or suggest Windows C++, Credential Providers, or LSA packages.
- **Android Only:** All project code is Android/Kotlin.

## 2. Production Code Quality
- **Language:** Kotlin (latest stable).
- **Concurrency:** Use Kotlin Coroutines and Flows for BLE and asynchronous operations. No raw threads or RxJava.
- **Static Analysis:** Code must be structured to pass `ktlint` and `detekt` without suppressing critical warnings.
- **Error Handling:** Never swallow exceptions. Log non-sensitive errors appropriately and return standardized CTAP2 error codes to the BLE client.

## 3. Mandatory Security Requirements (CRITICAL)
- **Hardware-Backed Keystore:** Private keys MUST be generated and stored inside the Android Keystore. Explicitly attempt to use `StrongBox`. Never generate asymmetric keys in software and never export private keys.
- **Biometric Gating:** Every signature operation must be guarded by a `BiometricPrompt` wrapping a `CryptoObject`.
- **Enrollment Invalidation:** Keys must use `setInvalidatedByBiometricEnrollment(true)`.
- **Zero Logging of Secrets:** NEVER log `clientDataHash`, private keys, public keys, or signatures.
- **Memory Hygiene:** Clear sensitive byte arrays from memory immediately after use.
- **Standard Algorithms:** Only use ECDSA with P-256 (NIST secp256r1) as required by the CTAP2 specification (`ES256`).

## 4. Dependencies
- Use `androidx.biometric:biometric` for biometric prompts.
- Use a robust, actively maintained CBOR library (e.g., `kotlinx.serialization` with CBOR, or `jackson-dataformat-cbor`). Do not write a custom CBOR parser.

## 5. Naming & Structure
- Adhere to the CTAP2 specification terminology (`authenticatorMakeCredential`, `authenticatorGetAssertion`, `clientDataHash`, `attestationObject`).
- Name BLE characteristics explicitly based on the specification (e.g., `FidoControlPointCharacteristic`).
