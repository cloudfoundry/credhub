package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.cloudfoundry.credhub.view.DataResponse;
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

  public DataResponse getCurrentCredentialVersions(
      String credentialName,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    List<CredentialVersion> credentialVersions = credentialService.findActiveByName(credentialName, auditRecordParametersList);

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return DataResponse.fromEntity(credentialVersions);

  }

  public CredentialView getCredentialVersionByUUID(
      String credentialUUID,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return CredentialView.fromEntity(credentialService.findVersionByUuid(credentialUUID, auditRecordParametersList));
  }
}
