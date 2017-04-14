package io.pivotal.security.service;

import static com.google.common.collect.Lists.newArrayList;
import static org.apache.commons.lang3.ArrayUtils.toPrimitive;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import java.nio.charset.Charset;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class EncryptionKeyCanaryMapper {

  public static final Charset CHARSET = Charset.defaultCharset();
  public static final String CANARY_VALUE = new String(new byte[128], CHARSET);
  public static final String DEPRECATED_CANARY_VALUE = new String(new byte[64], CHARSET);

  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionKeysConfiguration encryptionKeysConfiguration;
  private final BiMap<UUID, Key> encryptionKeyMap;

  private UUID activeUuid;
  private List<KeyProxy> keys;
  private KeyProxy activeKey;
  private EncryptionService encryptionService;

  @Autowired
  EncryptionKeyCanaryMapper(
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService,
      EncryptionKeysConfiguration encryptionKeysConfiguration,
      EncryptionService encryptionService) {
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
    this.encryptionKeysConfiguration = encryptionKeysConfiguration;
    this.encryptionService = encryptionService;

    encryptionKeyMap = HashBiMap.create();

    mapUuidsToKeys();
  }

  public void mapUuidsToKeys() {
    encryptionKeyMap.clear();
    createKeys();
    mapCanariesToKeys();
  }

  public List<Key> getKeys() {
    return keys.stream().map(k -> k.getKey()).collect(Collectors.toList());
  }

  public Key getActiveKey() {
    return activeKey.getKey();
  }

  public Key getKeyForUuid(UUID uuid) {
    return encryptionKeyMap.get(uuid);
  }

  public UUID getUuidForKey(Key key) {
    return encryptionKeyMap.inverse().get(key);
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
    encryptionKeyMap.clear();
    List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();

    validateActiveKeyInList(activeKey, keys);
    populateActiveCanary(activeKey, encryptionKeyCanaries);
    populateCanariesForNonActiveKeys(activeKey, encryptionKeyCanaries, keys);
  }

  private void validateActiveKeyInList(KeyProxy key, List<KeyProxy> encryptionKeys) {
    final Optional<KeyProxy> firstMatchingKey = encryptionKeys.stream().filter(k -> key.equals(k))
        .findFirst();
    // This could be refactored to orElseThrow except there is a bug in the JDK :(
    if (!firstMatchingKey.isPresent()) {
      throw new RuntimeException("No active key was found");
    }
  }

  private void populateActiveCanary(KeyProxy activeEncryptionKey,
      List<EncryptionKeyCanary> encryptionKeyCanaries) {
    EncryptionKeyCanary activeCanary = findCanaryMatchingKey(activeEncryptionKey,
        encryptionKeyCanaries).orElseGet(() -> createCanary(activeEncryptionKey));
    activeUuid = activeCanary.getUuid();
    encryptionKeyMap.put(activeCanary.getUuid(), activeEncryptionKey.getKey());
  }

  private void populateCanariesForNonActiveKeys(KeyProxy activeEncryptionKey,
      List<EncryptionKeyCanary> encryptionKeyCanaries, List<KeyProxy> encryptionKeys) {
    final Stream<KeyProxy> nonActiveKeys = encryptionKeys.stream()
        .filter(encryptionKey -> !activeEncryptionKey.equals(encryptionKey));
    nonActiveKeys.forEach(encryptionKey -> {
      findCanaryMatchingKey(encryptionKey, encryptionKeyCanaries)
          .ifPresent(canary -> encryptionKeyMap.put(canary.getUuid(), encryptionKey.getKey()));
    });
  }

  private Optional<EncryptionKeyCanary> findCanaryMatchingKey(KeyProxy encryptionKey,
      List<EncryptionKeyCanary> canaries) {
    return canaries.stream().filter(canary -> encryptionKey.matchesCanary(canary)).findFirst();
  }

  private EncryptionKeyCanary createCanary(KeyProxy encryptionKey) {
    EncryptionKeyCanary canary = new EncryptionKeyCanary();

    try {
      Encryption encryptionData = encryptionService
          .encrypt(null, encryptionKey.getKey(), CANARY_VALUE);
      canary.setEncryptedCanaryValue(encryptionData.encryptedValue);
      canary.setNonce(encryptionData.nonce);
      final List<Byte> salt = encryptionKey.getSalt();
      final Byte[] saltArray = new Byte[salt.size()];
      canary.setSalt(toPrimitive(salt.toArray(saltArray)));

    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return encryptionKeyCanaryDataService.save(canary);
  }
}
