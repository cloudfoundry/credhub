package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
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
  private final CEFAuditRecord auditRecord;

  @Autowired
  public CredentialsHandler(PermissionedCredentialService credentialService, CEFAuditRecord auditRecord) {
    this.credentialService = credentialService;
    this.auditRecord = auditRecord;
  }

  public void deleteCredential(String credentialName) {
    boolean deleteSucceeded = credentialService.delete(credentialName);
    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public DataResponse getNCredentialVersions(String credentialName, Integer numberOfVersions) {
    List<CredentialVersion> credentialVersions;
    if (numberOfVersions == null) {
      credentialVersions = credentialService.findAllByName(credentialName);
    } else {
      credentialVersions = credentialService.findNByName(credentialName, numberOfVersions);

      for (CredentialVersion credentialVersion : credentialVersions) {
        auditRecord.addResource(credentialVersion);
      }
    }

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return DataResponse.fromEntity(credentialVersions);
  }

  public DataResponse getAllCredentialVersions(String credentialName) {
    return getNCredentialVersions(credentialName, null);
  }

  public DataResponse getCurrentCredentialVersions(String credentialName) {
    List<CredentialVersion> credentialVersions = credentialService.findActiveByName(credentialName);

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return DataResponse.fromEntity(credentialVersions);

  }

  public CredentialView getCredentialVersionByUUID(String credentialUUID) {
    return CredentialView.fromEntity(credentialService.findVersionByUuid(credentialUUID));
  }
}
