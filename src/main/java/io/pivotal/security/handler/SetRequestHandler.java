package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.CredentialService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SetRequestHandler {

  private CredentialService credentialService;

  @Autowired
  public SetRequestHandler(CredentialService credentialService) {
    this.credentialService = credentialService;
  }

  public CredentialView handle(UserContext userContext,
      List<EventAuditRecordParameters> eventAuditRecordParameters,
      BaseCredentialSetRequest setRequest,
      PermissionEntry currentEntry) {

    StringGenerationParameters generationParameters = null;

    if (setRequest instanceof PasswordSetRequest) {
      generationParameters = ((PasswordSetRequest) setRequest).getGenerationParameters();
    }

    return credentialService.save(
        userContext,
        eventAuditRecordParameters,
        setRequest.getName(),
        setRequest.isOverwrite(),
        setRequest.getType(),
        generationParameters,
        setRequest.getCredentialValue(),
        setRequest.getAdditionalPermissions(),
        currentEntry);
  }
}
