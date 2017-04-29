package io.pivotal.security.handler;

import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.exceptions.EntryNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CredentialHandler {
  private final CredentialDataService credentialDataService;

  @Autowired
  public CredentialHandler(CredentialDataService credentialDataService) {
    this.credentialDataService = credentialDataService;
  }

  public void deleteCredential(String credentialName) {
    boolean deleteSucceeded = credentialDataService.delete(credentialName);

    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential_not_found");
    }
  }
}
