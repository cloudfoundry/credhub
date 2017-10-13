package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.CredentialView;
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

    final CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion, generateRequest.getName(),
        generateRequest.getType(),
        value,
        generateRequest.getGenerationParameters(),
        generateRequest.getAdditionalPermissions(),
        generateRequest.getOverwriteMode(),
        auditRecordParameters
    );

    final boolean isNewCredential = existingCredentialVersion == null;

    if (isNewCredential || generateRequest.isOverwrite()) {
      permissionService.savePermissions(credentialVersion, generateRequest.getAdditionalPermissions(), auditRecordParameters, isNewCredential, generateRequest.getName());
    }

    return CredentialView.fromEntity(credentialVersion);
  }
}
