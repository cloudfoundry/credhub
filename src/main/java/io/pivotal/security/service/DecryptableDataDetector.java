package io.pivotal.security.service;

import io.pivotal.security.data.SecretDataService;
import java.util.ArrayList;
import java.util.UUID;

public class DecryptableDataDetector {

  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private SecretDataService secretDataService;

  DecryptableDataDetector(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      SecretDataService secretDataService) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.secretDataService = secretDataService;
  }

  public void check() {
    ArrayList<UUID> uuids = encryptionKeyCanaryMapper.getKnownCanaryUuids();

    Long countTotalSecrets = secretDataService.count();
    Long countSecretsEncryptedWithKeyWeHave = secretDataService.countEncryptedWithKeyUuidIn(uuids);
    if (countTotalSecrets > 0 && countSecretsEncryptedWithKeyWeHave == 0) {
      throw new RuntimeException(
          "The encryption keys provided cannot decrypt any of the " + countTotalSecrets
              + " value(s) in the database. "
              + "Please make sure you've provided the necessary encryption keys.");
    }
  }
}
