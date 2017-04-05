package io.pivotal.security.regeneratables;

import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.view.ResponseError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class PasswordSecret implements Regeneratable {

  private final ErrorResponseService responseService;
  private GenerateService generateService;

  public PasswordSecret(ErrorResponseService responseService, GenerateService generateService) {
    this.responseService = responseService;
    this.generateService = generateService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    NamedPasswordSecret passwordSecret = (NamedPasswordSecret) secret;
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setName(passwordSecret.getName());
    generateRequest.setType(passwordSecret.getSecretType());
    PasswordGenerationParameters generationParameters;
    try {
      generationParameters = passwordSecret.getGenerationParameters();
    } catch (KeyNotFoundException e) {
      ResponseError errorResponse = responseService.createErrorResponse("error.missing_encryption_key");
      return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    if (generationParameters == null) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_password");
    }
    generateRequest.setGenerationParameters(generationParameters);

    return generateService.performGenerate(auditRecordBuilder, generateRequest);
  }
}
