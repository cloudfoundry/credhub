package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GenerateHandler {

  private final PermissionedCredentialService credentialService;
  private final UniversalCredentialGenerator credentialGenerator;

  @Autowired
  public GenerateHandler(
      PermissionedCredentialService credentialService,
      UniversalCredentialGenerator credentialGenerator) {
    this.credentialService = credentialService;
    this.credentialGenerator = credentialGenerator;
  }

  public CredentialView handle(
      BaseCredentialGenerateRequest generateRequest,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    CredentialValue value = credentialGenerator.generate(generateRequest, userContext);

    return credentialService.save(
        generateRequest.getName(),
        generateRequest.getType(),
        value,
        generateRequest.getGenerationParameters(),
        generateRequest.getAdditionalPermissions(),
        generateRequest.isOverwrite(),
        userContext,
        currentUserPermissionEntry,
        auditRecordParameters
    );
  }
}
