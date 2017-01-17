package io.pivotal.security.service;

import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.pivotal.security.service.EncryptionKeyService.CHARSET;

@Component
public class EncryptionKeyCanaryMapper {
  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionService encryptionService;
  static final String CANARY_VALUE = new String(new byte[128], CHARSET);
  private static final String WRONG_CANARY_PLAINTEXT = "WRONG KEY FOR CANARY";
  private final Map<UUID, Key> encryptionKeyMap;

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

  public Map<UUID, Key> getEncryptionKeyMap() {
    return encryptionKeyMap;
  }

  public UUID getActiveUuid() {
    return activeUuid;
  }

  private void mapCanariesToKeys() {
    List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();
    Key activeEncryptionKey = encryptionService.getActiveKey();
    List<Key> encryptionKeys = encryptionService.getKeys();

    boolean foundActiveKey = false;

    for (Key encryptionKey : encryptionKeys) {
      boolean isActiveEncryptionKey = activeEncryptionKey.equals(encryptionKey);
      foundActiveKey = foundActiveKey || isActiveEncryptionKey;
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

    if (!foundActiveKey) {
      throw new RuntimeException("No active key was found");
    }
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
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return CANARY_VALUE.equals(plaintext);
  }

  private EncryptionKeyCanary findMatchingCanary(Key encryptionKey, List<EncryptionKeyCanary> canaries) {
    for (EncryptionKeyCanary canary : canaries) {
      if (isMatchingCanary(encryptionKey, canary)) {
        return canary;
      }
    }

    return null;
  }
}
