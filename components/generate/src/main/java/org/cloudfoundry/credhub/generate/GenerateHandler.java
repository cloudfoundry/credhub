package org.cloudfoundry.credhub.generate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.services.PermissionedCredentialService;
import org.cloudfoundry.credhub.views.CredentialView;

@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "This will be refactored into safer non-nullable types"
)
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
