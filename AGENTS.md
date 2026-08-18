# Agent Customizations & Rules for Phone2PC

This file contains strict rules for AI coding assistants and developers working on this repository. Adherence is mandatory to maintain production-grade security, code quality, and disciplined development workflows.

---

## 1. Development Discipline & Workflow Rules
- **Step-by-Step Execution:** Never execute or complete bulk tasks all at once. Break down tasks into small, discrete, verifiable steps and proceed incrementally.
- **Review Before Coding:** Continuously review your code and ask: *Is this actually necessary and optimal?* Avoid speculative abstractions and premature optimizations.
- **Root-Cause Problem Solving:** If an issue or bug occurs, always investigate and solve the **root cause**. Never apply cosmetic patches, hacky workarounds, or swallow errors.
- **Impact & Regression Analysis:** Before making any change to the codebase, check all call sites and dependencies to ensure the modification will not break other components.
- **Concise & Minimal Solutions:** Do NOT write 100 lines of boilerplate for a 4-line solution. Keep implementations focused, readable, and elegant.
- **Minimal Dependencies:** Do NOT import unnecessary packages or third-party libraries. Rely on official Android/Kotlin APIs and existing project dependencies whenever possible.

---

## 2. Architecture & Protocol Constraints
- **Strict FIDO2 / CTAP2:** This project is a FIDO2 CTAP2 BLE roaming authenticator. You must adhere strictly to the FIDO Alliance specifications.
- **NO WINDOWS CODE:** The PC side relies entirely on native Windows Hello functionality. Do not write or suggest Windows C++, Credential Providers, or LSA packages.
- **Android Only:** All project code is Android/Kotlin.

---

## 3. Production Code Quality & Scalability
- **Language:** Kotlin (latest stable, modern idioms).
- **Architecture:** Clean Architecture with feature-based packaging (`ble`, `ctap`, `crypto`, `biometric`, `model`, `ui`).
- **Concurrency:** Use Kotlin Coroutines and Flows for BLE and asynchronous operations. No raw threads or RxJava.
- **Static Analysis:** Code must be structured to pass `ktlint` and `detekt` without suppressing critical warnings.
- **Error Handling:** Never swallow exceptions. Log non-sensitive errors appropriately and return standardized CTAP2 error codes to the BLE client.

---

## 4. Mandatory Security Requirements (CRITICAL)
- **Hardware-Backed Keystore:** Private keys MUST be generated and stored inside the Android Keystore. Explicitly attempt to use `StrongBox` (fallback to standard TEE). Never generate asymmetric keys in software and never export private keys.
- **Biometric Gating:** Every signature operation must be guarded by a `BiometricPrompt` wrapping a `CryptoObject`.
- **Enrollment Invalidation:** Keys must use `setInvalidatedByBiometricEnrollment(true)`.
- **Zero Logging of Secrets:** NEVER log `clientDataHash`, private keys, public keys, nonces, or signatures.
- **Memory Hygiene:** Clear sensitive byte arrays from memory immediately after use.
- **Standard Algorithms:** Only use ECDSA with P-256 (NIST secp256r1) as required by the CTAP2 specification (`ES256`).

---

## 5. Third-Party Dependencies
- Use `androidx.biometric:biometric` for biometric prompts.
- Use `kotlinx.serialization` with CBOR for CTAP2 message serialization/deserialization. Do not write custom CBOR parsers or pull in unvetted third-party crypto libraries.

---

## 6. Naming & Structure
- Adhere strictly to the CTAP2 specification terminology (`authenticatorMakeCredential`, `authenticatorGetAssertion`, `clientDataHash`, `attestationObject`).
- Name BLE characteristics explicitly based on the specification (e.g., `FidoControlPointCharacteristic`).
