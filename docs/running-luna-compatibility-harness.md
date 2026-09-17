# Running the Luna HSM Compatibility Test Harness

This document describes how to configure, execute, and interpret CredHub's opt-in Luna Hardware Security Module (HSM) compatibility test suite.

---

## 1. Overview and Purpose

CredHub supports Thales/SafeNet Luna HSM as an external cryptographic provider via Java Cryptography Architecture (JCA) integration. The test suite defined in `LunaHsmCompatibilityTest.java` validates CredHub's Luna JCA integration directly against a physical HSM partition at the code level.

The compatibility harness verifies:
1. **AES GCM Parameter Specification & Roundtrip**: Reflective instantiation of `com.safenetinc.luna.provider.param.LunaGcmParameterSpec` and real hardware AES-128 GCM encryption and decryption.
2. **Key Creation & Keystore Reuse**: Creation of hardware-backed AES keys in the HSM KeyStore and subsequent retrieval without creating duplicate keys.
3. **Canary Validation & Error Text Inspection**: Proper canary matching (`LunaKeyProxy`) and logging of exception cause chains to verify whether Luna Client 10.9.x still produces `returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)` on key mismatches.
4. **Session Reconnection (Disruptive)**: Automatic recovery and re-authentication after unexpected session drop or forced logout.

### Tagged Isolation & Skip Behavior
The tests are categorized into two JUnit 5 tags:
* `@Tag("luna-hsm")`: Non-disruptive tests (tests 1–3).
* `@Tag("luna-hsm-disruptive")`: Disruptive tests that force session logout (test 4).

Both tags are **excluded by default** in standard `./gradlew test` runs. Furthermore, `@BeforeAll` guards check for the presence of required environment variables (`LUNA_HSM_PARTITION` and `LUNA_HSM_PARTITION_PASSWORD`) via `Assumptions.assumeTrue(...)`. If either variable is missing or empty, tests report **SKIPPED** without error, ensuring CI pipelines and local developer builds are never broken. Per-test key cleanup tracking is initialized in `@BeforeEach` and purged in `@AfterEach`.

---

## 2. CRITICAL SAFETY WARNING: Credential Lockout & Zeroization Risk

> :warning: **DANGER: RISK OF PERMANENT DATA LOSS**
>
> Luna HSM partitions enforce a **bad-login attempt counter** (typically between 3 and 10 attempts). If consecutive failed login attempts exceed the partition threshold, the HSM **permanently locks or zeroizes (erases) the partition**, destroying all keys and data!

### Mandatory Pre-Flight Verification
* **NEVER** run the Gradle test tasks with unverified credentials or typos in `LUNA_HSM_PARTITION_PASSWORD`.
* **ALWAYS** verify connectivity and credentials out-of-band using `lunacm` before invoking Gradle:
  ```bash
  lunacm
  lunacm:> slot list
  lunacm:> slot set -slot <slot_id>
  lunacm:> role login -name co -password <CO_PASSWORD>
  lunacm:> partition showinfo
  lunacm:> role logout
  lunacm:> exit
  ```
* If `lunacm` authentication fails, resolve the credential issue with your HSM administrator. Do **NOT** retry repeatedly.

---

## 3. Host and OS Prerequisites

Executing the compatibility harness against a physical or cloud HSM requires a Linux runtime environment with the SafeNet/Thales Luna Client installed.

### Option A: Linux Host (Physical Appliance or VM)
1. **Luna Client Installation**: SafeNet Luna Client package (e.g., 10.9.x) installed on the system (usually under `/usr/safenet/lunaclient/`).
2. **Configuration File (`/etc/Chrystoki.conf`)**:
   * Must point to valid client certificate and private key paths.
   * Must include the Luna HSM server CA certificate.
   * Example Chrystoki configuration excerpt:
     ```ini
     Chrystoki2 = {
       LibUNIX = /usr/safenet/lunaclient/lib/libCryptoki2.so;
       LibUNIX64 = /usr/safenet/lunaclient/lib/libCryptoki2_64.so;
     }
     Luna = {
       DefaultTimeOut = 20000;
       PEDTimeout1 = 100000;
       PEDTimeout2 = 200000;
       PEDTimeout3 = 10000;
       KeypairGenTimeOut = 270000;
       ClLogging = 1;
       LogToFile = /var/log/lunaclient.log;
     }
     CardProc = {
       ServerCAFile = /usr/safenet/lunaclient/cert/server/server.pem;
     }
     ```
3. **Mutual TLS Registration**:
   * HSM server CA registered with `vtl addServer`.
   * Client certificate created and registered on the Luna appliance via `client register`.
   * Client assigned to the partition via `client assignPartition`.
4. **Network Connectivity**:
   * TCP port **1792** (NTLS) must be open and reachable between the host running the tests and the Luna HSM appliance.
   * Verify using:
     ```bash
     vtl verify
     ```

### Option B: macOS / Docker Execution Environment (Cloud HSM or Remote Appliance)
The SafeNet/Thales Luna JCA integration relies on Java Native Interface (JNI) to load native C libraries (`libLunaAPI.so`, `libCryptoki2.so`). Because Thales distributes Linux ELF shared libraries and Windows DLLs (with no macOS Mach-O `.dylib` distribution), macOS hosts cannot load the Luna client libraries natively. Furthermore, Apple Silicon (M1-M4) Macs use ARM64 architecture while Luna client binaries are `x86_64` (`amd64`).

To run the harness on macOS or containerized environments:
1. Use Docker with `--platform linux/amd64` emulation (supported via Rosetta 2 or QEMU in Docker Desktop).
2. Use a base image matching CredHub's target runtime (e.g. `bellsoft/liberica-openjdk-debian:25`).
3. Unpack the client package (e.g. Thales Data Protection on Demand DPoD client package or SafeNet Linux client) into a mounted directory (e.g. `/opt/dpod-client`).
4. Ensure `ChrystokiConfigurationPath` points to the client configuration directory.
5. Example Docker execution:
   ```bash
   docker run --platform linux/amd64 --rm -it \
     -v "$PWD":/workspace \
     -v "/path/to/client":/opt/dpod-client \
     -w /workspace \
     -e LUNA_HSM_PARTITION="<partition-name>" \
     -e LUNA_HSM_PARTITION_PASSWORD="<partition-password>" \
     -e LUNA_PROVIDER_JAR="/opt/dpod-client/jsp/LunaProvider.jar" \
     -e LUNA_NATIVE_LIB_DIR="/opt/dpod-client/jsp/64" \
     -e ChrystokiConfigurationPath="/opt/dpod-client" \
     bellsoft/liberica-openjdk-debian:25 \
     ./gradlew :components:encryption:lunaHsmCompatTest
   ```

---

## 4. Environment Variables

The Gradle tasks and test harness require four environment variables:

| Variable | Description | Example |
|---|---|---|
| `LUNA_HSM_PARTITION` | Name of the Luna HSM partition assigned for testing. | `credhub-test-partition` |
| `LUNA_HSM_PARTITION_PASSWORD` | Crypto Officer / User password for the partition. | `SecretPassw0rd!` |
| `LUNA_PROVIDER_JAR` | Absolute path to the SafeNet `LunaProvider.jar`. Added to the test runtime classpath. | `/usr/safenet/lunaclient/jsp/lib/LunaProvider.jar` |
| `LUNA_NATIVE_LIB_DIR` | Directory containing native libraries (`libLunaAPI.so`, `libJCProv.so`). Passed to JVM via `-Djava.library.path`. | `/usr/safenet/lunaclient/jsp/lib` |

---

## 5. Execution Commands

### A. Non-Disruptive Compatibility Suite (`lunaHsmCompatTest`)
Runs tests 1–3 (`encryptDecrypt_roundTripsThroughRealGcmCipher`, `createKeyProxy_createsThenReusesRealKey`, and `matchesCanary_trueForOwnKey_falseForCanaryEncryptedUnderAnotherRealKey`):

```bash
export LUNA_HSM_PARTITION="<partition-name>"
export LUNA_HSM_PARTITION_PASSWORD="<partition-password>"
export LUNA_PROVIDER_JAR="/usr/safenet/lunaclient/jsp/lib/LunaProvider.jar"
export LUNA_NATIVE_LIB_DIR="/usr/safenet/lunaclient/jsp/lib"

./gradlew :components:encryption:lunaHsmCompatTest
```

### B. Disruptive Compatibility Suite (`lunaHsmDisruptiveTest`)
Runs test 4 (`reconnectAfterForcedLogout_restoresLoginState`), which forcefully terminates the active Luna slot session:

```bash
export LUNA_HSM_PARTITION="<partition-name>"
export LUNA_HSM_PARTITION_PASSWORD="<partition-password>"
export LUNA_PROVIDER_JAR="/usr/safenet/lunaclient/jsp/lib/LunaProvider.jar"
export LUNA_NATIVE_LIB_DIR="/usr/safenet/lunaclient/jsp/lib"

./gradlew :components:encryption:lunaHsmDisruptiveTest
```

### C. Standard Build Isolation Check
Verify that default test tasks do not trigger HSM operations:

```bash
./gradlew :components:encryption:test
```
Result: All Luna HSM compatibility tests are excluded from execution.

---

## 6. Test Suite Details

### Test 1: `encryptDecrypt_roundTripsThroughRealGcmCipher()`
* **Tag**: `luna-hsm`
* **Validation**:
  * Asserts `generateParameterSpec(null) != null`, ensuring `com.safenetinc.luna.provider.param.LunaGcmParameterSpec` is instantiated reflectively with AAD and tag length.
  * Encrypts plaintext using hardware AES-GCM cipher (`Cipher.getInstance("AES/GCM/NoPadding", provider)`).
  * Validates IV / nonce generation and successful roundtrip decryption.

### Test 2: `createKeyProxy_createsThenReusesRealKey()`
* **Tag**: `luna-hsm`
* **Validation**:
  * Creates a key with UUID alias `credhub-compat-test-<uuid>`.
  * Calls `createKeyProxy` a second time with the same alias.
  * Asserts that `containsAlias` is true, no duplicate key is generated, and data encrypted by the first proxy decrypts successfully with the second proxy.

### Test 3: `matchesCanary_trueForOwnKey_falseForCanaryEncryptedUnderAnotherRealKey()`
* **Tag**: `luna-hsm`
* **Validation**:
  * Generates Key A and Key B.
  * Encrypts canary value with Key A and verifies `proxyA.matchesCanary(canary) == true`.
  * Attempts direct decryption of the canary using Key B to capture the exact exception cause chain.
  * Traverses and prints all exception causes to stdout and logger:
    ```
    === Captured Key B decryption exception cause chain for analysis ===
    Cause level [0] (...): ...
    Cause level [1] (...): ...
    ====================================================================
    ```
  * Validates that `proxyB.matchesCanary(canary) == false`.
  * **Key Diagnostic Objective**: Determines whether Luna Client 10.9.x returns `returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)` as expected by `LunaKeyProxy.java` or if the error message format has changed in 10.9.x.

### Test 4: `reconnectAfterForcedLogout_restoresLoginState()`
* **Tag**: `luna-hsm-disruptive`
* **Validation**:
  * Confirms session is initially logged in (`lunaConnection.isLoggedIn() == true`).
  * Reflectively invokes `LunaSlotManager.getInstance().logout()`.
  * Asserts session is logged out (`lunaConnection.isLoggedIn() == false`).
  * Calls `lunaEncryptionService.reconnect(...)` and verifies session is restored (`lunaConnection.isLoggedIn() == true`).
  * Performs encryption and decryption to confirm the reconnected session is operational.

---

## 7. Keystore Cleanup Semantics

* Test keys are created with the prefix `credhub-compat-test-<uuid>`.
* In `@AfterEach`, the harness attempts to delete created keys via `KeyStore.deleteEntry(alias)`.
* **Important Note**: Some Luna JCA provider versions or partition configurations do not permit key deletion via JCA `KeyStore.deleteEntry()`. The harness catches any exception during deletion and logs a warning rather than failing the test suite.
* **Empirical Validation (Luna Client 10.9.x)**: Key deletion via `KeyStore.deleteEntry(alias)` was empirically verified on Luna Client 10.9.x. All generated keys were deleted cleanly without throwing exceptions, and partition inspection (`lunacm:> partition showinfo`) confirmed `Object Count: 0` and `Used Storage Space: 0`, confirming zero key accumulation.
* Following live test execution, inspect partition contents using `lunacm`:
  ```bash
  lunacm:> partition showcontents
  ```
  If test keys remain, clean them up or adjust partition policies as needed.

---

## 8. Safety Cautions & Gating for Disruptive Testing

Before executing `./gradlew :components:encryption:lunaHsmDisruptiveTest`:

1. **Partition Dedication**:
   * Ensure the partition is dedicated exclusively for test purposes.
   * **Do NOT** execute disruptive tests against a shared partition where active CredHub instances, applications, or other team members are actively performing operations.
2. **Host-Level Impact**:
   * `LunaSlotManager.logout()` operates at the JVM / client-process level for the active slot. It logs out all connections utilizing that slot manager.
3. **High-Availability (HA) Topology**:
   * If the client configuration uses an HA group (`HA = 1` in `Chrystoki.conf`), forced logout on an individual member slot may trigger failover or error logging across the HA cluster. Consult your HSM administrator before running disruptive tests against HA clusters.

---

## 9. Empirical Validation Results & Canary Findings (Luna Client 10.9.x)

The compatibility harness was executed against a live Luna Cloud HSM (Thales DPoD) partition utilizing the SafeNet Luna Client 10.9.x runtime inside a `linux/amd64` Docker environment (`bellsoft/liberica-openjdk-debian:25`).

### A. Test Execution Summary

| Task | Tests Run | Passed | Failed | Skipped | Duration |
|---|---|---|---|---|---|
| `:components:encryption:lunaHsmCompatTest` | 3 | 3 | 0 | 0 | 34.1s |
| `:components:encryption:lunaHsmDisruptiveTest` | 1 | 1 | 0 | 0 | 28.2s |
| `:components:encryption:test` (Default build) | All | All | 0 | Luna tests excluded | - |

### B. Canary Exception Code Analysis (Test 3)

The highest-value diagnostic objective of the harness was capturing the live exception chain thrown when decrypting ciphertext under an incorrect hardware AES key.

CredHub's `LunaKeyProxy.java` inspects the exception cause string to distinguish wrong-key decryption failure from other operational errors:
```java
// LunaKeyProxy.java:64-66
private boolean errorIsSomethingOtherThanTheKeyBeingIncorrect(final Exception e) {
  return e.getCause() == null || !e.getCause().getMessage().contains("returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)");
}
```

During execution of `matchesCanary_trueForOwnKey_falseForCanaryEncryptedUnderAnotherRealKey()`, direct decryption of the Key A canary with Key B produced the following cause chain:
```text
=== Captured Key B decryption exception cause chain for analysis ===
Cause level [0] (com.safenetinc.luna.exception.LunaException): Unable to perform cipher doFinal
Cause level [1] (com.safenetinc.luna.exception.LunaCryptokiException): function 'C_Decrypt' returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)
====================================================================
```

#### Key Findings & Implications:
1. **Exact Error Code Match**: The Luna Client 10.9.x runtime produces the exact substring `returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)` at `cause.getMessage()`.
2. **Zero Code Changes Needed**: CredHub's existing canary verification in `LunaKeyProxy` is 100% compatible with Luna Client 10.9.x without requiring any changes or modernization to exception parsing.
3. **Canary Logic Verification**: `proxyA.matchesCanary(canary)` returned `true` for its own key, and `proxyB.matchesCanary(canary)` cleanly returned `false` without throwing an unhandled `RuntimeException`.

### C. Keystore Reuse & Cleanup Verification (Test 2 & `@AfterEach`)

* **Keystore Reuse (Test 2)**: Verified that calling `lunaEncryptionService.createKeyProxy(alias)` twice with the same alias successfully retrieved the existing hardware AES key (`lunaConnection.containsAlias(alias) == true`) without re-generating or creating duplicate keys on the partition.
* **KeyStore Deletion (`@AfterEach`)**: Every generated test key was deleted via `keyStore.deleteEntry(alias)` during test tear-down.
* **Partition Object Verification**: Pre- and post-test verification via `lunacm` confirmed that the partition was left completely clean:
  ```text
  Partition Storage:
      Total Storage Space:  159744
      Used Storage Space:   0
      Free Storage Space:   159744
      Object Count:         0
  ```
  This proves that Luna JCA `KeyStore.deleteEntry(alias)` is fully supported on Luna Client 10.9.x and there is zero test key leakage.

### D. Disruptive Session Recovery (Test 4)

Test 4 (`reconnectAfterForcedLogout_restoresLoginState`) verified that:
1. `LunaSlotManager.getInstance().logout()` terminates the active Cryptoki session (`isLoggedIn() == false`).
2. `lunaEncryptionService.reconnect(...)` successfully re-initializes, re-authenticates to the partition, and restores login state (`isLoggedIn() == true`).
3. Subsequent cryptographic operations (generating a fresh AES-128 key and performing GCM encryption/decryption) succeeded immediately on the restored session.

### E. Test Lifecycle Architecture Note

`LunaSlotManager` is a native JVM-wide singleton interacting directly with `libLunaAPI.so` / `libCryptoki2.so`. In CredHub's production runtime (`EncryptionProviderFactory`), `LunaConnection` is created once as a singleton service and shared across all encryption requests.

In `LunaHsmCompatibilityTest.java`, initializing `LunaConnection` once in `@BeforeAll` (rather than per-method in `@BeforeEach`) aligns the test suite with production architecture, avoiding uninitialized KeyStore state when re-entering already-authenticated native sessions, while per-test key tracking in `@BeforeEach`/`@AfterEach` ensures clean per-test isolation.
