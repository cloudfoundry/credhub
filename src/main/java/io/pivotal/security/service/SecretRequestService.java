package io.pivotal.security.service;

import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.request.BaseSecretRequest;
import io.pivotal.security.view.ResponseError;
import io.pivotal.security.view.SecretView;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class SecretRequestService {

  private final MessageSourceAccessor messageSourceAccessor;
  private final SecretGenerator passwordGenerator;
  private SecretDataService secretDataService;
  private AuditLogService auditLogService;
  private Encryptor encryptor;
  private HashMap<String, SecretGenerator> generators = new HashMap<>();

  public SecretRequestService(SecretDataService secretDataService,
      AuditLogService auditLogService,
      Encryptor encryptor,
      MessageSource messageSource,
      PassayStringSecretGenerator passwordGenerator) {
    this.secretDataService = secretDataService;
    this.auditLogService = auditLogService;
    this.encryptor = encryptor;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
    this.passwordGenerator = passwordGenerator;
  }

  public ResponseEntity perform(
      AuditRecordBuilder auditRecordBuilder,
      BaseSecretRequest requestBody
  ) throws Exception {
    final String secretName = requestBody.getName();

    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean shouldWriteNewEntity = existingNamedSecret == null || requestBody.isOverwrite();

    auditRecordBuilder
        .setOperationCode(shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS);

    return auditLogService.performWithAuditing(auditRecordBuilder, () -> {
      try {
        final String type = requestBody.getType();
        validateSecretType(existingNamedSecret, type);

        NamedSecret storedEntity = existingNamedSecret;
        if (shouldWriteNewEntity) {
          NamedSecret newEntity = requestBody
              .createNewVersion(existingNamedSecret, encryptor, getGeneratorFor(type));
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
    });
  }

  private SecretGenerator getGeneratorFor(String type) {
    generators.put(NamedPasswordSecretData.SECRET_TYPE, passwordGenerator);
    return generators.get(type);
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
