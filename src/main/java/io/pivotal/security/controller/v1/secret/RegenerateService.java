package io.pivotal.security.controller.v1.secret;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.view.ResponseError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
class RegenerateService {
  private final ErrorResponseService errorResponseService;
  private SecretDataService secretDataService;
  private GenerateService generateService;

  RegenerateService(
      ErrorResponseService errorResponseService,
      SecretDataService secretDataService,
      GenerateService generateService
  ) {
    this.errorResponseService = errorResponseService;
    this.secretDataService = secretDataService;
    this.generateService = generateService;
  }

  ResponseEntity performRegenerate(AuditRecordBuilder auditRecordBuilder, SecretRegenerateRequest requestBody) {
    NamedSecret secret = secretDataService.findMostRecent(requestBody.getName());

    if (secret instanceof NamedPasswordSecret) {
      NamedPasswordSecret passwordSecret = (NamedPasswordSecret) secret;
      PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

      generateRequest.setName(passwordSecret.getName());
      generateRequest.setType(passwordSecret.getSecretType());
      PasswordGenerationParameters generationParameters;
      try {
        generationParameters = passwordSecret.getGenerationParameters();
      } catch (KeyNotFoundException e) {
        ResponseError errorResponse = errorResponseService.createErrorResponse("error.missing_encryption_key");
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
      }

      if (generationParameters == null) {
        throw new ParameterizedValidationException(
            "error.cannot_regenerate_non_generated_password");
      }
      generateRequest.setGenerationParameters(generationParameters);

      return generateService.performGenerate(auditRecordBuilder, generateRequest);
    }

    return null;
  }
}
