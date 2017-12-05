package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static org.apache.commons.lang3.ArrayUtils.toPrimitive;

@Component
public class EncryptionKeyCanaryMapper {

  public static final Charset CHARSET = Charset.defaultCharset();
  public static final String CANARY_VALUE = new String(new byte[128], CHARSET);
  public static final String DEPRECATED_CANARY_VALUE = new String(new byte[64], CHARSET);
  public static final int CANARY_POPULATION_WAIT_SEC = 60 * 10; // ten minutes

  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionKeysConfiguration encryptionKeysConfiguration;
  private final Map<UUID, Key> encryptionKeyMap;
  private final TimedRetry timedRetry;
  private final boolean keyCreationEnabled;

  private UUID activeUuid;
  private List<KeyProxy> keys;
  private KeyProxy activeKey;
  private EncryptionService encryptionService;
  private final Logger logger;

  @Autowired
  EncryptionKeyCanaryMapper(
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService,
      EncryptionKeysConfiguration encryptionKeysConfiguration,
      EncryptionService encryptionService,
      TimedRetry timedRetry,
      @Value("${encryption.key_creation_enabled}") boolean keyCreationEnabled
  ) {
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
    this.encryptionKeysConfiguration = encryptionKeysConfiguration;
    this.encryptionService = encryptionService;
    this.timedRetry = timedRetry;
    this.keyCreationEnabled = keyCreationEnabled;

    logger = LogManager.getLogger();
    encryptionKeyMap = new HashMap<>();

    mapUuidsToKeys();
  }

  public void mapUuidsToKeys() {
    encryptionKeyMap.clear();
    createKeys();
    validateActiveKeyInList();
    createOrFindActiveCanary();
    mapCanariesToKeys();
  }

  public List<Key> getKeys() {
    return keys.stream().map(KeyProxy::getKey).collect(Collectors.toList());
  }

  public Key getActiveKey() {
    return activeKey.getKey();
  }

  public Key getKeyForUuid(UUID uuid) {
    return encryptionKeyMap.get(uuid);
  }

  public UUID getActiveUuid() {
    return activeUuid;
  }

  public ArrayList<UUID> getKnownCanaryUuids() {
    return new ArrayList<>(encryptionKeyMap.keySet());
  }

  public List<UUID> getCanaryUuidsWithKnownAndInactiveKeys() {
    List<UUID> list = getKnownCanaryUuids();
    list.removeIf((uuid) -> activeUuid.equals(uuid));
    return list;
  }

  private void createKeys() {
    keys = newArrayList();
    encryptionKeysConfiguration.getKeys().forEach(keyMetadata -> {
      KeyProxy keyProxy = encryptionService.createKeyProxy(keyMetadata);
      keys.add(keyProxy);
      if (keyMetadata.isActive()) {
        activeKey = keyProxy;
      }
    });
  }

  private void mapCanariesToKeys() {
    List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();

    populateCanaries(encryptionKeyCanaries);
  }

  private void validateActiveKeyInList() {
    if (activeKey == null || !keys.contains(activeKey)) {
      throw new RuntimeException("No active key was found");
    }
  }

  private void populateCanaries(List<EncryptionKeyCanary> encryptionKeyCanaries) {
    keys.forEach(encryptionKey -> {
      findCanaryMatchingKey(encryptionKey, encryptionKeyCanaries)
          .ifPresent(canary -> encryptionKeyMap.put(canary.getUuid(), encryptionKey.getKey()));
    });
  }

  private Optional<EncryptionKeyCanary> findCanaryMatchingKey(KeyProxy encryptionKey,
      List<EncryptionKeyCanary> canaries) {
    return canaries.stream().filter(encryptionKey::matchesCanary).findFirst();
  }

  private void createOrFindActiveCanary() {
    EncryptionKeyCanary[] activeCanary = new EncryptionKeyCanary[1];

    if (keyCreationEnabled) {
      activeCanary[0] =
          findCanaryMatchingKey(activeKey, encryptionKeyCanaryDataService.findAll())
              .orElseGet(() -> {
                logger.info("Creating a new active key canary");
                EncryptionKeyCanary canary = new EncryptionKeyCanary();

                try {
                  EncryptedValue encryptionData = encryptionService
                      .encrypt(null, activeKey.getKey(), CANARY_VALUE);
                  canary.setEncryptedCanaryValue(encryptionData.getEncryptedValue());
                  canary.setNonce(encryptionData.getNonce());
                  final List<Byte> salt = activeKey.getSalt();
                  final Byte[] saltArray = new Byte[salt.size()];
                  canary.setSalt(toPrimitive(salt.toArray(saltArray)));

                } catch (Exception e) {
                  throw new RuntimeException(e);
                }

                return encryptionKeyCanaryDataService.save(canary);
              });
    } else {
      timedRetry.retryEverySecondUntil(CANARY_POPULATION_WAIT_SEC, () -> {
        activeCanary[0] = findCanaryMatchingKey(activeKey, encryptionKeyCanaryDataService.findAll())
            .orElseGet(() -> {
              logger.info("Waiting for the active key's canary");
              return null;
            });
        return activeCanary[0] != null;
      });
    }

    activeUuid = activeCanary[0].getUuid();
  }
}
