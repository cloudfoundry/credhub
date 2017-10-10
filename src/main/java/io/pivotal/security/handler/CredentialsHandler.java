package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
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

  public void deleteCredential(String credentialName, UserContext userContext, List<EventAuditRecordParameters> eventAuditRecordParametersList) {
    boolean deleteSucceeded = credentialService.delete(userContext, credentialName, eventAuditRecordParametersList);
    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public List<CredentialVersion> getNCredentialVersions(
      String credentialName,
      Integer numberOfVersions, UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    List<CredentialVersion> credentialVersions;
    if (numberOfVersions == null) {
      credentialVersions = credentialService.findAllByName(userContext, credentialName, auditRecordParametersList);
    } else {
      credentialVersions = credentialService.findNByName(userContext, credentialName, numberOfVersions, auditRecordParametersList);
    }

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersions;
  }

  public List<CredentialVersion> getAllCredentialVersions(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return getNCredentialVersions(credentialName, null, userContext, auditRecordParametersList);
  }

  public CredentialVersion getMostRecentCredentialVersion(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    CredentialVersion credentialVersion =
        getNCredentialVersions(credentialName, 1, userContext, auditRecordParametersList)
            .get(0);

    return credentialVersion;
  }

  public CredentialVersion getCredentialVersionByUUID(
      String credentialUUID,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return credentialService.findByUuid(userContext, credentialUUID, auditRecordParametersList);
  }
}
