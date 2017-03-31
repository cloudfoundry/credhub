package io.pivotal.security.service;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.view.ResponseError;
import io.pivotal.security.view.SecretView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class SecretRequestService {

  private final MessageSourceAccessor messageSourceAccessor;
  private SecretDataService secretDataService;
  private Encryptor encryptor;
  private GeneratorService generatorService;

  @Autowired
  public SecretRequestService(
      SecretDataService secretDataService,
      Encryptor encryptor,
      MessageSource messageSource,
      GeneratorService generatorService) {
    this.secretDataService = secretDataService;
    this.encryptor = encryptor;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
    this.generatorService = generatorService;
  }

  public ResponseEntity performGenerate(
      AuditRecordBuilder auditRecordBuilder,
      BaseSecretGenerateRequest requestBody
  ) throws Exception {
    BaseSecretSetRequest setRequest = requestBody.generateSetRequest(generatorService);
    return performSet(auditRecordBuilder, setRequest);
  }

  public ResponseEntity performSet(
      AuditRecordBuilder auditRecordBuilder,
      BaseSecretSetRequest requestBody
  ) throws Exception {
    final String secretName = requestBody.getName();

    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean shouldWriteNewEntity = existingNamedSecret == null || requestBody.isOverwrite();

    auditRecordBuilder
        .setOperationCode(shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS);

    try {
      final String type = requestBody.getType();
      validateSecretType(existingNamedSecret, type);

      NamedSecret storedEntity = existingNamedSecret;
      if (shouldWriteNewEntity) {
        NamedSecret newEntity = requestBody.createNewVersion(existingNamedSecret, encryptor);
        storedEntity = secretDataService.save(newEntity);
      }

      SecretView secretView = SecretView.fromEntity(storedEntity);
      return new ResponseEntity<>(secretView, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return new ResponseEntity<>(createParameterizedErrorResponse(ve), HttpStatus.BAD_REQUEST);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (KeyNotFoundException e) {
      return new ResponseEntity<>(createErrorResponse("error.missing_encryption_key"),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private void validateSecretType(NamedSecret existingNamedSecret, String secretType) {
    if (existingNamedSecret != null && !existingNamedSecret.getSecretType().equals(secretType)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }

  private ResponseError createErrorResponse(String key) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key));
  }

  private ResponseError createParameterizedErrorResponse(
      ParameterizedValidationException exception) {
    String errorMessage = messageSourceAccessor
        .getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseError(errorMessage);
  }

}
