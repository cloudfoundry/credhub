package io.pivotal.security.service;

import io.pivotal.security.data.CredentialVersionDataService;
import java.util.ArrayList;
import java.util.UUID;

public class DecryptableDataDetector {

  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private CredentialVersionDataService credentialVersionDataService;

  DecryptableDataDetector(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
                          CredentialVersionDataService credentialVersionDataService) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  public void check() {
    ArrayList<UUID> uuids = encryptionKeyCanaryMapper.getKnownCanaryUuids();

    Long countTotalCredentials = credentialVersionDataService.count();
    Long countCredentialsEncryptedWithKeyWeHave = credentialVersionDataService.countEncryptedWithKeyUuidIn(uuids);
    if (countTotalCredentials > 0 && countCredentialsEncryptedWithKeyWeHave == 0) {
      throw new RuntimeException(
          "The encryption keys provided cannot decrypt any of the " + countTotalCredentials
              + " value(s) in the database. "
              + "Please make sure you've provided the necessary encryption keys.");
    }
  }
}
