package io.pivotal.security.service;

import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static io.pivotal.security.service.EncryptionKey.CHARSET;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.AEADBadTagException;

@Component
public class EncryptionKeyCanaryMapper {
  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionService encryptionService;
  static final String CANARY_VALUE = new String(new byte[128], CHARSET);
  private static final String WRONG_CANARY_PLAINTEXT = "WRONG KEY FOR CANARY";
  private final Map<UUID, EncryptionKey> encryptionKeyMap;

  private UUID activeUuid;

  @Autowired
  EncryptionKeyCanaryMapper(
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService,
      EncryptionService encryptionService
  ) {
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
    this.encryptionService = encryptionService;

    encryptionKeyMap = new HashMap<>();

    mapCanariesToKeys();
  }

  public Map<UUID, EncryptionKey> getEncryptionKeyMap() {
    return encryptionKeyMap;
  }

  public UUID getActiveUuid() {
    return activeUuid;
  }

  private void mapCanariesToKeys() {
    List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();
    EncryptionKey activeEncryptionKey = encryptionService.getActiveKey();
    List<EncryptionKey> encryptionKeys = encryptionService.getKeys();

    for (EncryptionKey encryptionKey : encryptionKeys) {
      boolean isActiveEncryptionKey = activeEncryptionKey.equals(encryptionKey);
      EncryptionKeyCanary matchingCanary = findMatchingCanary(encryptionKey, encryptionKeyCanaries);

      if (matchingCanary == null && isActiveEncryptionKey) {
        matchingCanary = createCanary(encryptionKey);
      }

      if (matchingCanary != null) {
        encryptionKeyMap.put(matchingCanary.getUuid(), encryptionKey);

        if (isActiveEncryptionKey) {
          activeUuid = matchingCanary.getUuid();
        }
      }
    }
  }

  private EncryptionKeyCanary createCanary(EncryptionKey encryptionKey) {
    EncryptionKeyCanary canary = new EncryptionKeyCanary();

    try {
      Encryption encryptionData = encryptionKey.encrypt(CANARY_VALUE);
      canary.setEncryptedValue(encryptionData.encryptedValue);
      canary.setNonce(encryptionData.nonce);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return encryptionKeyCanaryDataService.save(canary);
  }

  private boolean isMatchingCanary(EncryptionKey encryptionKey, EncryptionKeyCanary canary) {
    String plaintext;

    try {
      plaintext = encryptionKey.decrypt(canary.getEncryptedValue(), canary.getNonce());
    } catch (AEADBadTagException e) {
      plaintext = WRONG_CANARY_PLAINTEXT;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return CANARY_VALUE.equals(plaintext);
  }

  private EncryptionKeyCanary findMatchingCanary(EncryptionKey encryptionKey, List<EncryptionKeyCanary> canaries) {
    for (EncryptionKeyCanary canary : canaries) {
      if (isMatchingCanary(encryptionKey, canary)) {
        return canary;
      }
    }

    return null;
  }
}
