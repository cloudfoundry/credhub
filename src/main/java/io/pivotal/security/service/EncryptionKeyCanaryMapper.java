package io.pivotal.security.service;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.google.common.collect.Lists.newArrayList;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

@Component
public class EncryptionKeyCanaryMapper {
  public static final Charset CHARSET = Charset.defaultCharset();
  public static final String CANARY_VALUE = new String(new byte[128], CHARSET);

  private static final String WRONG_CANARY_PLAINTEXT = "WRONG KEY FOR CANARY";
  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionKeysConfiguration encryptionKeysConfiguration;
  private final EncryptionService encryptionService;
  private final BiMap<UUID, Key> encryptionKeyMap;

  private UUID activeUuid;
  private List<Key> keys;
  private Key activeKey;

  @Autowired
  EncryptionKeyCanaryMapper(
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService,
      EncryptionKeysConfiguration encryptionKeysConfiguration,
      EncryptionService encryptionService
  ) {
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
    this.encryptionKeysConfiguration = encryptionKeysConfiguration;
    this.encryptionService = encryptionService;

    encryptionKeyMap = HashBiMap.create();

    mapUuidsToKeys();
  }

  public void mapUuidsToKeys() {
    createKeys();
    mapCanariesToKeys();
  }

  public List<Key> getKeys() {
    return keys;
  }

  public Key getActiveKey() {
    return activeKey;
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

  private void createKeys() {
    keys = newArrayList();
    encryptionKeysConfiguration.getKeys().forEach(keyMetadata -> {
      Key key = encryptionService.createKey(keyMetadata);
      keys.add(key);
      if (keyMetadata.isActive()) {
        activeKey = key;
      }
    });
  }

  private void mapCanariesToKeys() {
    encryptionKeyMap.clear();
    List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();

    ensureKeyIsInList(activeKey, keys);
    populateActiveCanary(activeKey, encryptionKeyCanaries);
    populateCanariesForNonActiveKeys(activeKey, encryptionKeyCanaries, keys);
  }

  private void ensureKeyIsInList(Key key, List<Key> encryptionKeys) {
    final Optional<Key> firstMatchingKey = encryptionKeys.stream().filter(k -> key.equals(k)).findFirst();
    // TODO this could be refactored to orElseThrow except there is a bug in the JDK :(
    if (!firstMatchingKey.isPresent()) {
      throw new RuntimeException("No active key was found");
    }
  }

  private void populateActiveCanary(Key activeEncryptionKey, List<EncryptionKeyCanary> encryptionKeyCanaries) {
    EncryptionKeyCanary activeCanary = findCanaryMatchingKey(activeEncryptionKey, encryptionKeyCanaries).orElseGet(() -> createCanary(activeEncryptionKey));
    activeUuid = activeCanary.getUuid();
    encryptionKeyMap.put(activeCanary.getUuid(), activeEncryptionKey);
  }

  private void populateCanariesForNonActiveKeys(Key activeEncryptionKey, List<EncryptionKeyCanary> encryptionKeyCanaries, List<Key> encryptionKeys) {
    final Stream<Key> nonActiveKeys = encryptionKeys.stream().filter(encryptionKey -> !activeEncryptionKey.equals(encryptionKey));
    nonActiveKeys.forEach(encryptionKey -> {
      findCanaryMatchingKey(encryptionKey, encryptionKeyCanaries).ifPresent(canary -> encryptionKeyMap.put(canary.getUuid(), encryptionKey));
    });
  }

  private Optional<EncryptionKeyCanary> findCanaryMatchingKey(Key encryptionKey, List<EncryptionKeyCanary> canaries) {
    return canaries.stream().filter(canary -> isMatchingCanary(encryptionKey, canary)).findFirst();
  }

  private EncryptionKeyCanary createCanary(Key encryptionKey) {
    EncryptionKeyCanary canary = new EncryptionKeyCanary();

    try {
      Encryption encryptionData = encryptionService.encrypt(encryptionKey, CANARY_VALUE);
      canary.setEncryptedValue(encryptionData.encryptedValue);
      canary.setNonce(encryptionData.nonce);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return encryptionKeyCanaryDataService.save(canary);
  }

  private boolean isMatchingCanary(Key encryptionKey, EncryptionKeyCanary canary) {
    String plaintext;

    try {
      plaintext = encryptionService.decrypt(encryptionKey, canary.getEncryptedValue(), canary.getNonce());
    } catch (AEADBadTagException e) {
      // dev_internal key was wrong
      plaintext = WRONG_CANARY_PLAINTEXT;
    } catch (IllegalBlockSizeException e) {
      // Our guess(es) at "HSM key was wrong":
      if (e.getMessage().contains("returns 0x40")) { // Could not process input data: function 'C_Decrypt' returns 0x40
        plaintext = WRONG_CANARY_PLAINTEXT;
      } else {
        throw new RuntimeException(e);
      }
    } catch (BadPaddingException e) {
      // Our guess(es) at "DSM key was wrong":
      if (e.getMessage().contains("rv=48")) { // javax.crypto.BadPaddingException: Decrypt error: rv=48
        plaintext = WRONG_CANARY_PLAINTEXT;
      } else {
        throw new RuntimeException(e);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return CANARY_VALUE.equals(plaintext);
  }
}
