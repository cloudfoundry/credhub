package org.cloudfoundry.credhub.handler;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.cloudfoundry.credhub.view.DataResponse;

@Component
public class CredentialsHandler {

  private final PermissionedCredentialService credentialService;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public CredentialsHandler(final PermissionedCredentialService credentialService, final CEFAuditRecord auditRecord) {
    super();
    this.credentialService = credentialService;
    this.auditRecord = auditRecord;
  }

  public void deleteCredential(final String credentialName) {
    final boolean deleteSucceeded = credentialService.delete(credentialName);
    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public DataResponse getNCredentialVersions(final String credentialName, final Integer numberOfVersions) {
    final List<CredentialVersion> credentialVersions;
    if (numberOfVersions == null) {
      credentialVersions = credentialService.findAllByName(credentialName);
    } else {
      credentialVersions = credentialService.findNByName(credentialName, numberOfVersions);

      for (final CredentialVersion credentialVersion : credentialVersions) {
        auditRecord.addVersion(credentialVersion);
        auditRecord.addResource(credentialVersion.getCredential());
      }
    }

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return DataResponse.fromEntity(credentialVersions);
  }

  public DataResponse getAllCredentialVersions(final String credentialName) {
    return getNCredentialVersions(credentialName, null);
  }

  public DataResponse getCurrentCredentialVersions(final String credentialName) {
    final List<CredentialVersion> credentialVersions = credentialService.findActiveByName(credentialName);

    if (credentialVersions.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return DataResponse.fromEntity(credentialVersions);

  }

  public CredentialView getCredentialVersionByUUID(final String credentialUUID) {
    return CredentialView.fromEntity(credentialService.findVersionByUuid(credentialUUID));
  }
}
