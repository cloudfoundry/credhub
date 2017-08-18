package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.domain.CredentialValueFactory;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.service.CredentialService;
import io.pivotal.security.service.GeneratorService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GenerateRequestHandler {

  private final GeneratorService generatorService;
  private final CredentialService credentialService;

  @Autowired
  public GenerateRequestHandler(GeneratorService generatorService, CredentialService credentialService) {
    this.generatorService = generatorService;
    this.credentialService = credentialService;
  }

  public CredentialView handle(
      UserContext userContext,
      List<EventAuditRecordParameters> parametersList,
      BaseCredentialGenerateRequest requestBody,
      PermissionEntry currentUserPermissionEntry) {

    CredentialValue value = CredentialValueFactory.generateValue(requestBody, generatorService);

    StringGenerationParameters generationParameters = null;
    if (requestBody instanceof PasswordGenerateRequest) {
      generationParameters = ((PasswordGenerateRequest) requestBody).getGenerationParameters();
    }

    if (requestBody instanceof UserGenerateRequest) {
      generationParameters = ((UserGenerateRequest) requestBody).getPasswordGenerationParameters();
    }

    return credentialService.save(
        userContext,
        parametersList,
        requestBody.getName(),
        requestBody.isOverwrite(),
        requestBody.getType(),
        generationParameters,
        value,
        requestBody.getAdditionalPermissions(),
        currentUserPermissionEntry);
  }
}
