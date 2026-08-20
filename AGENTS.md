# Agent Customizations & Rules for Phone2PC

This file contains strict rules for AI coding assistants and developers working on this repository. Adherence is mandatory to maintain production-grade security, code quality, and disciplined development workflows.

---

## 1. Development Discipline & Workflow Rules
- **Step-by-Step Execution:** Never execute or complete bulk tasks all at once. Break down tasks into small, discrete, verifiable steps and proceed incrementally.
- **Review Before Coding:** Continuously review your code and ask: *Is this actually necessary and optimal?* Avoid speculative abstractions and premature optimizations.
- **Root-Cause Problem Solving:** If an issue or bug occurs, always investigate and solve the **root cause**. Never apply cosmetic patches, hacky workarounds, or swallow errors.
- **Impact & Regression Analysis:** Before making any change to the codebase, check all call sites and dependencies to ensure the modification will not break other components.
- **Concise & Minimal Solutions:** Do NOT write 100 lines of boilerplate for a 4-line solution. Keep implementations focused, readable, and elegant.
- **Minimal Dependencies:** Do NOT import unnecessary packages or third-party libraries. Rely on official platform APIs and existing project dependencies whenever possible.

---

## 2. Architecture & Protocol Constraints
- **Strict FIDO2 / CTAP2:** This project is a FIDO2 CTAP2 BLE roaming authenticator. You must adhere strictly to the FIDO Alliance specifications.
- **Dual Platform:**
  - **Android (Authenticator):** Kotlin — the phone acts as a FIDO2 BLE GATT server.
  - **Windows (Unlock Client):** C# / .NET 8 — a desktop app that acts as a CTAP2 BLE GATT client, connecting to the phone to unlock the PC.
- **Windows client code lives in `windows/` directory.** Android code stays in `app/`.
- **No C++ Credential Providers or LSA packages.** The Windows client uses DPAPI + programmatic unlock, not a custom credential provider.

---

## 3. Production Code Quality & Scalability

### Android (Authenticator)
- **Language:** Kotlin (latest stable, modern idioms).
- **Architecture:** Clean Architecture with feature-based packaging (`ble`, `ctap`, `crypto`, `biometric`, `model`, `ui`).
- **Concurrency:** Use Kotlin Coroutines and Flows for BLE and asynchronous operations. No raw threads or RxJava.
- **Static Analysis:** Code must be structured to pass `ktlint` and `detekt` without suppressing critical warnings.
- **Error Handling:** Never swallow exceptions. Log non-sensitive errors appropriately and return standardized CTAP2 error codes to the BLE client.

### Windows (Unlock Client)
- **Language:** C# 12 / .NET 8.
- **Architecture:** Clean separation — BLE communication, CTAP2 protocol, credential management, and UI as distinct layers.
- **Concurrency:** Use async/await and Task-based patterns. No raw threads.
- **Error Handling:** Never swallow exceptions. Use structured logging. Never expose raw Windows credentials in logs or error messages.

---

## 4. Mandatory Security Requirements (CRITICAL)

### Android
- **Hardware-Backed Keystore:** Private keys MUST be generated and stored inside the Android Keystore. Explicitly attempt to use `StrongBox` (fallback to standard TEE). Never generate asymmetric keys in software and never export private keys.
- **Biometric Gating:** Every signature operation must be guarded by a `BiometricPrompt` wrapping a `CryptoObject`.
- **Enrollment Invalidation:** Keys must use `setInvalidatedByBiometricEnrollment(true)`.
- **Zero Logging of Secrets:** NEVER log `clientDataHash`, private keys, public keys, nonces, or signatures.
- **Memory Hygiene:** Clear sensitive byte arrays from memory immediately after use.
- **Standard Algorithms:** Only use ECDSA with P-256 (NIST secp256r1) as required by the CTAP2 specification (`ES256`).

### Windows
- **DPAPI for Credential Storage:** Windows credentials MUST be encrypted using DPAPI (`ProtectedData.Protect`). Never store plaintext passwords.
- **Zero Logging of Credentials:** NEVER log Windows passwords, FIDO2 assertions, or PIN tokens.
- **BLE Proximity:** Unlock should only work when the phone is within BLE range (inherent to BLE).
- **No Credential Transmission:** Windows credentials must NEVER be sent over BLE. Only FIDO2 assertions travel over the air.

---

## 5. Third-Party Dependencies

### Android
- Use `androidx.biometric:biometric` for biometric prompts.
- Use `kotlinx.serialization` with CBOR for CTAP2 message serialization/deserialization. Do not write custom CBOR parsers or pull in unvetted third-party crypto libraries.

### Windows
- Use `Windows.Devices.Bluetooth` (WinRT) for BLE communication.
- Use `System.Security.Cryptography.ProtectedData` (DPAPI) for credential encryption.
- Minimal NuGet dependencies — prefer built-in .NET APIs.

---

## 6. Naming & Structure
- Adhere strictly to the CTAP2 specification terminology (`authenticatorMakeCredential`, `authenticatorGetAssertion`, `clientDataHash`, `attestationObject`).
- Name BLE characteristics explicitly based on the specification (e.g., `FidoControlPointCharacteristic`).
- Windows project uses `Phone2PC.Desktop` namespace.
