package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.DataResponse;
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

  public DataResponse getNCredentialVersions(
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
    return DataResponse.fromEntity(credentialVersions);
  }

  public DataResponse getAllCredentialVersions(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return getNCredentialVersions(credentialName, null, auditRecordParametersList);
  }

  public DataResponse getMostRecentCredentialVersion(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return getNCredentialVersions(credentialName, 1, auditRecordParametersList);

  }

  public CredentialView getCredentialVersionByUUID(
      String credentialUUID,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return CredentialView.fromEntity(credentialService.findByUuid(credentialUUID, auditRecordParametersList));
  }
}
