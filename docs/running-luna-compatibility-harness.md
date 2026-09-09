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

Both tags are **excluded by default** in standard `./gradlew test` runs. Furthermore, `@BeforeEach` guards check for the presence of required environment variables (`LUNA_HSM_PARTITION` and `LUNA_HSM_PARTITION_PASSWORD`) via `Assumptions.assumeTrue(...)`. If either variable is missing or empty, tests report **SKIPPED** without error, ensuring CI pipelines and local developer builds are never broken.

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
  lunacm:> partition login -partition <PARTITION_NAME> -password <PARTITION_PASSWORD>
  lunacm:> partition logout
  lunacm:> exit
  ```
* If `lunacm` authentication fails, resolve the credential issue with your HSM administrator. Do **NOT** retry repeatedly.

---

## 3. Host and OS Prerequisites

Executing the compatibility harness against a physical HSM requires a properly provisioned host machine (typically Linux) with the SafeNet/Thales Luna Client installed:

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
