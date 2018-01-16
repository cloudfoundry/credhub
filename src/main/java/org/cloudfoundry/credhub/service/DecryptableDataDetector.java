package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.UUID;

@Component
public class DecryptableDataDetector {

  private EncryptionKeySet keySet;
  private CredentialVersionDataService credentialVersionDataService;

  DecryptableDataDetector(EncryptionKeySet keySet,
                          CredentialVersionDataService credentialVersionDataService) {
    this.keySet = keySet;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  public void check() {
    Collection<UUID> uuids = keySet.getUuids();

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
