package io.pivotal.security.service;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.view.ResponseError;
import io.pivotal.security.view.SecretView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class SetService {
  private final ErrorResponseService errorResponseService;
  private final Encryptor encryptor;
  private final SecretDataService secretDataService;

  @Autowired
  public SetService(ErrorResponseService errorResponseService,
                    SecretDataService secretDataService,
                    Encryptor encryptor
  ) {
    this.errorResponseService = errorResponseService;
    this.secretDataService = secretDataService;
    this.encryptor = encryptor;
  }

  public ResponseEntity performSet(AuditRecordBuilder auditRecordBuilder, BaseSecretSetRequest requestBody) {
    final String secretName = requestBody.getName();

    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean shouldWriteNewEntity = existingNamedSecret == null || requestBody.isOverwrite();

    auditRecordBuilder.setOperationCode(shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS);

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
      return new ResponseEntity<>(errorResponseService.createParameterizedErrorResponse(ve), HttpStatus.BAD_REQUEST);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (KeyNotFoundException e) {
      ResponseError errorResponse = errorResponseService.createErrorResponse("error.missing_encryption_key");
      return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private void validateSecretType(NamedSecret existingNamedSecret, String secretType) {
    if (existingNamedSecret != null && !existingNamedSecret.getSecretType().equals(secretType)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }
}
