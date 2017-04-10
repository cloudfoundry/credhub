package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import org.springframework.http.ResponseEntity;

public class PasswordSecret implements Regeneratable {

  private GenerateService generateService;

  public PasswordSecret(GenerateService generateService) {
    this.generateService = generateService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    NamedPasswordSecret passwordSecret = (NamedPasswordSecret) secret;
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setName(passwordSecret.getName());
    generateRequest.setType(passwordSecret.getSecretType());
    PasswordGenerationParameters generationParameters;
    generationParameters = passwordSecret.getGenerationParameters();

    if (generationParameters == null) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_password");
    }
    generateRequest.setGenerationParameters(generationParameters);

    return generateService.performGenerate(auditRecordBuilder, generateRequest);
  }
}
