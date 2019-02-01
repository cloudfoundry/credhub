package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class GenerateHandler {

  private final PermissionedCredentialService credentialService;
  private final UniversalCredentialGenerator credentialGenerator;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public GenerateHandler(
    final PermissionedCredentialService credentialService,
    final UniversalCredentialGenerator credentialGenerator,
    final CEFAuditRecord auditRecord) {
    super();
    this.credentialService = credentialService;
    this.credentialGenerator = credentialGenerator;
    this.auditRecord = auditRecord;
  }

  public CredentialView handle(final BaseCredentialGenerateRequest generateRequest) {
    final CredentialVersion existingCredentialVersion = credentialService.findMostRecent(generateRequest.getName());
    final CredentialValue value = credentialGenerator.generate(generateRequest);

    final CredentialVersion credentialVersion = credentialService.save(existingCredentialVersion, value, generateRequest);

    auditRecord.setVersion(credentialVersion);
    auditRecord.setResource(credentialVersion.getCredential());
    return CredentialView.fromEntity(credentialVersion);
  }
}
