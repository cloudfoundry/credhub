package org.cloudfoundry.credhub.services;

import java.util.Collection;
import java.util.UUID;

import org.springframework.stereotype.Component;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

@Component
@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "Let's refactor this class into kotlin"
)
public class DefaultDecryptableDataDetector implements DecryptableDataDetector {

  private final EncryptionKeySet keySet;
  private final CredentialVersionDataService credentialVersionDataService;

  DefaultDecryptableDataDetector(
    final EncryptionKeySet keySet,
    final CredentialVersionDataService credentialVersionDataService
  ) {
    super();
    this.keySet = keySet;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  @Override
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
