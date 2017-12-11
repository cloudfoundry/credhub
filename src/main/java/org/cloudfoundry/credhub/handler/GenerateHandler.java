package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GenerateHandler {

  private final PermissionedCredentialService credentialService;
  private PermissionService permissionService;
  private final UniversalCredentialGenerator credentialGenerator;

  @Autowired
  public GenerateHandler(
      PermissionedCredentialService credentialService,
      PermissionService permissionService, UniversalCredentialGenerator credentialGenerator) {
    this.credentialService = credentialService;
    this.permissionService = permissionService;
    this.credentialGenerator = credentialGenerator;
  }

  public CredentialView handle(
      BaseCredentialGenerateRequest generateRequest,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(generateRequest.getName());
    CredentialValue value = credentialGenerator.generate(generateRequest);

    final CredentialVersion credentialVersion = credentialService.save(existingCredentialVersion, value, generateRequest, auditRecordParameters);

    final boolean isNewCredential = existingCredentialVersion == null;

    if (isNewCredential || generateRequest.isOverwrite()) {
      permissionService.savePermissions(credentialVersion, generateRequest.getAdditionalPermissions(), auditRecordParameters, isNewCredential, generateRequest.getName());
    }

    return CredentialView.fromEntity(credentialVersion);
  }
}
