package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.service.PermissionedCredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CredentialsHandler {
  private final PermissionedCredentialService credentialService;

  @Autowired
  public CredentialsHandler(PermissionedCredentialService credentialService) {
    this.credentialService = credentialService;
  }

  public void deleteCredential(String credentialName, List<EventAuditRecordParameters> eventAuditRecordParametersList) {
    boolean deleteSucceeded = credentialService.delete(credentialName, eventAuditRecordParametersList);
    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public List<CredentialVersion> getNCredentialVersions(
      String credentialName,
      Integer numberOfVersions,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    List<CredentialVersion> credentialVersions;
    if (numberOfVersions == null) {
      credentialVersions = credentialService.findAllByName(credentialName, auditRecordParametersList);
    } else {
      credentialVersions = credentialService.findNByName(credentialName, numberOfVersions, auditRecordParametersList);
    }

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersions;
  }

  public List<CredentialVersion> getAllCredentialVersions(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return getNCredentialVersions(credentialName, null, auditRecordParametersList);
  }

  public CredentialVersion getMostRecentCredentialVersion(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    CredentialVersion credentialVersion =
        getNCredentialVersions(credentialName, 1, auditRecordParametersList)
            .get(0);

    return credentialVersion;
  }

  public CredentialVersion getCredentialVersionByUUID(
      String credentialUUID,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return credentialService.findByUuid(credentialUUID, auditRecordParametersList);
  }
}
