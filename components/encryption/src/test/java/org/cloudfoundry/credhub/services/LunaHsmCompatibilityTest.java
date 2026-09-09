package org.cloudfoundry.credhub.services;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionConfiguration;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;

public class LunaHsmCompatibilityTest {

  private static final Logger LOGGER = LogManager.getLogger(LunaHsmCompatibilityTest.class);
  private static final String LUNA_HSM_TAG = "luna-hsm";
  private static final String LUNA_HSM_DISRUPTIVE_TAG = "luna-hsm-disruptive";
  private static final String KEY_ALIAS_PREFIX = "credhub-compat-test-";
  private static final String LUNA_SLOT_MANAGER_CLASS = "com.safenetinc.luna.LunaSlotManager";

  private LunaConnection lunaConnection;
  private LunaEncryptionService lunaEncryptionService;
  private List<String> createdKeyAliases;

  @BeforeEach
  public void setUp() throws Exception {
    final String partition = System.getenv("LUNA_HSM_PARTITION");
    final String partitionPassword = System.getenv("LUNA_HSM_PARTITION_PASSWORD");

    Assumptions.assumeTrue(
      partition != null && !partition.trim().isEmpty()
        && partitionPassword != null && !partitionPassword.trim().isEmpty(),
      "Luna HSM environment variables (LUNA_HSM_PARTITION and LUNA_HSM_PARTITION_PASSWORD) are not set. "
        + "Skipping Luna HSM tests."
    );

    createdKeyAliases = new ArrayList<>();
    final EncryptionConfiguration configuration = new EncryptionConfiguration();
    configuration.setPartition(partition);
    configuration.setPartitionPassword(partitionPassword);

    lunaConnection = new LunaConnection(configuration);
    final TimedRetry timedRetry = new TimedRetry(new CurrentTimeProvider());
    lunaEncryptionService = new LunaEncryptionService(lunaConnection, true, timedRetry);
  }

  @AfterEach
  public void tearDown() {
    if (lunaConnection != null && createdKeyAliases != null) {
      for (final String alias : createdKeyAliases) {
        try {
          final Field keyStoreField = LunaConnection.class.getDeclaredField("keyStore");
          keyStoreField.setAccessible(true);
          final KeyStore keyStore = (KeyStore) keyStoreField.get(lunaConnection);
          if (keyStore != null && keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
            LOGGER.info("Successfully deleted test key alias '{}' from Luna KeyStore", alias);
          }
        } catch (final Exception e) {
          LOGGER.warn(
            "Failed to delete test key alias '{}' during cleanup. "
              + "The Luna JCA provider may not support deleteEntry(): {}",
            alias,
            e.getMessage()
          );
        }
      }
    }
  }

  @Test
  @Tag(LUNA_HSM_TAG)
  public void encryptDecrypt_roundTripsThroughRealGcmCipher() throws Exception {
    final AlgorithmParameterSpec nullIvSpec = lunaEncryptionService.generateParameterSpec(null);
    assertThat("generateParameterSpec(null) must return a LunaGcmParameterSpec instance", nullIvSpec, notNullValue());

    final String alias = KEY_ALIAS_PREFIX + UUID.randomUUID();
    createdKeyAliases.add(alias);
    final EncryptionKeyMetadata metadata = new EncryptionKeyMetadata();
    metadata.setEncryptionKeyName(alias);

    final KeyProxy keyProxy = lunaEncryptionService.createKeyProxy(metadata);
    final String plaintext = "test-plaintext-payload-" + UUID.randomUUID();

    final EncryptedValue encrypted = lunaEncryptionService.encrypt(UUID.randomUUID(), keyProxy.getKey(), plaintext);
    assertThat(encrypted, notNullValue());
    assertThat(encrypted.getEncryptedValue(), notNullValue());
    assertThat(encrypted.getNonce(), notNullValue());

    final String decrypted = lunaEncryptionService.decrypt(
      keyProxy.getKey(),
      encrypted.getEncryptedValue(),
      encrypted.getNonce()
    );
    assertThat(decrypted, equalTo(plaintext));
  }

  @Test
  @Tag(LUNA_HSM_TAG)
  public void createKeyProxy_createsThenReusesRealKey() throws Exception {
    final String alias = KEY_ALIAS_PREFIX + UUID.randomUUID();
    createdKeyAliases.add(alias);
    final EncryptionKeyMetadata metadata = new EncryptionKeyMetadata();
    metadata.setEncryptionKeyName(alias);

    final KeyProxy firstProxy = lunaEncryptionService.createKeyProxy(metadata);
    assertThat(firstProxy, notNullValue());
    assertThat(firstProxy.getKey(), notNullValue());
    assertThat(lunaConnection.containsAlias(alias), equalTo(true));

    final KeyProxy secondProxy = lunaEncryptionService.createKeyProxy(metadata);
    assertThat(secondProxy, notNullValue());
    assertThat(secondProxy.getKey(), notNullValue());

    final String plaintext = "reuse-test-plaintext-" + UUID.randomUUID();
    final EncryptedValue encrypted = lunaEncryptionService.encrypt(UUID.randomUUID(), firstProxy.getKey(), plaintext);
    final String decrypted = lunaEncryptionService.decrypt(
      secondProxy.getKey(),
      encrypted.getEncryptedValue(),
      encrypted.getNonce()
    );
    assertThat(decrypted, equalTo(plaintext));
  }

  @Test
  @Tag(LUNA_HSM_TAG)
  public void matchesCanary_trueForOwnKey_falseForCanaryEncryptedUnderAnotherRealKey() throws Exception {
    final String aliasA = KEY_ALIAS_PREFIX + UUID.randomUUID();
    final String aliasB = KEY_ALIAS_PREFIX + UUID.randomUUID();
    createdKeyAliases.add(aliasA);
    createdKeyAliases.add(aliasB);

    final EncryptionKeyMetadata metadataA = new EncryptionKeyMetadata();
    metadataA.setEncryptionKeyName(aliasA);
    final KeyProxy proxyA = lunaEncryptionService.createKeyProxy(metadataA);

    final EncryptionKeyMetadata metadataB = new EncryptionKeyMetadata();
    metadataB.setEncryptionKeyName(aliasB);
    final KeyProxy proxyB = lunaEncryptionService.createKeyProxy(metadataB);

    final EncryptedValue canaryEncryptedUnderA = lunaEncryptionService.encrypt(
      UUID.randomUUID(),
      proxyA.getKey(),
      CANARY_VALUE
    );

    final EncryptionKeyCanary canary = new EncryptionKeyCanary();
    canary.setEncryptedCanaryValue(canaryEncryptedUnderA.getEncryptedValue());
    canary.setNonce(canaryEncryptedUnderA.getNonce());

    // Canary must match for Key A
    final boolean matchesA = proxyA.matchesCanary(canary);
    assertThat("Key A must match canary encrypted under Key A", matchesA, equalTo(true));

    // Direct decryption under Key B to inspect and log the exact exception cause chain
    try {
      lunaEncryptionService.decrypt(
        proxyB.getKey(),
        canary.getEncryptedCanaryValue(),
        canary.getNonce()
      );
      Assertions.fail("Expected decryption with Key B to throw an exception, but it succeeded");
    } catch (final Exception e) {
      LOGGER.info("=== Captured Key B decryption exception cause chain for analysis ===");
      System.out.println("=== Captured Key B decryption exception cause chain for analysis ===");
      Throwable current = e;
      int depth = 0;
      while (current != null) {
        final String logMsg = String.format(
          "Cause level [%d] (%s): %s",
          depth,
          current.getClass().getName(),
          current.getMessage()
        );
        LOGGER.info(logMsg);
        System.out.println(logMsg);
        current = current.getCause();
        depth++;
      }
      LOGGER.info("====================================================================");
      System.out.println("====================================================================");
    }

    // Verify proxyB.matchesCanary(canary) returns false
    boolean matchesB = false;
    try {
      matchesB = proxyB.matchesCanary(canary);
    } catch (final RuntimeException e) {
      LOGGER.info("proxyB.matchesCanary threw RuntimeException: {}", e.getMessage());
      System.out.println("proxyB.matchesCanary threw RuntimeException: " + e.getMessage());
      Throwable current = e;
      int depth = 0;
      while (current != null) {
        final String logMsg = String.format(
          "matchesCanary cause [%d] (%s): %s",
          depth,
          current.getClass().getName(),
          current.getMessage()
        );
        LOGGER.info(logMsg);
        System.out.println(logMsg);
        current = current.getCause();
        depth++;
      }
    }
    assertThat("Key B must not match canary encrypted under Key A", matchesB, equalTo(false));
  }

  @Test
  @Tag(LUNA_HSM_DISRUPTIVE_TAG)
  public void reconnectAfterForcedLogout_restoresLoginState() throws Exception {
    assertThat("Luna session must initially be logged in", lunaConnection.isLoggedIn(), equalTo(true));

    final Object slotManager = Class.forName(LUNA_SLOT_MANAGER_CLASS)
      .getDeclaredMethod("getInstance")
      .invoke(null);

    slotManager.getClass().getMethod("logout").invoke(slotManager);
    assertThat("Luna session must be logged out after forced logout", lunaConnection.isLoggedIn(), equalTo(false));

    lunaEncryptionService.reconnect(new RuntimeException("Simulated forced logout reconnect test"));
    assertThat("Luna session must be logged in after reconnect", lunaConnection.isLoggedIn(), equalTo(true));

    final String alias = KEY_ALIAS_PREFIX + UUID.randomUUID();
    createdKeyAliases.add(alias);
    final EncryptionKeyMetadata metadata = new EncryptionKeyMetadata();
    metadata.setEncryptionKeyName(alias);

    final KeyProxy proxy = lunaEncryptionService.createKeyProxy(metadata);
    final String plaintext = "post-reconnect-test-" + UUID.randomUUID();
    final EncryptedValue encrypted = lunaEncryptionService.encrypt(UUID.randomUUID(), proxy.getKey(), plaintext);
    final String decrypted = lunaEncryptionService.decrypt(
      proxy.getKey(),
      encrypted.getEncryptedValue(),
      encrypted.getNonce()
    );
    assertThat(decrypted, equalTo(plaintext));
  }
}
