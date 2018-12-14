package org.cloudfoundry.credhub.service;

import java.util.Collection;
import java.util.UUID;

import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.data.CredentialVersionDataService;

@Component
public class DecryptableDataDetector {

  private final EncryptionKeySet keySet;
  private final CredentialVersionDataService credentialVersionDataService;

  DecryptableDataDetector(final EncryptionKeySet keySet,
                          final CredentialVersionDataService credentialVersionDataService) {
    super();
    this.keySet = keySet;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  public void check() {
    final Collection<UUID> uuids = keySet.getUuids();

    final Long countTotalCredentials = credentialVersionDataService.count();
    final Long countCredentialsEncryptedWithKeyWeHave = credentialVersionDataService.countEncryptedWithKeyUuidIn(uuids);
    if (countTotalCredentials > 0 && countCredentialsEncryptedWithKeyWeHave == 0) {
      throw new RuntimeException(
        "The encryption keys provided cannot decrypt any of the " + countTotalCredentials
          + " value(s) in the database. "
          + "Please make sure you've provided the necessary encryption keys.");
    }
  }
}
