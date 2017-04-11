package io.pivotal.security.service;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

import io.pivotal.security.audit.AuditRecordBuilder;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.view.SecretView;
import java.security.NoSuchAlgorithmException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class SetService {
  private final Encryptor encryptor;
  private final SecretDataService secretDataService;

  @Autowired
  public SetService(SecretDataService secretDataService,
                    Encryptor encryptor
  ) {
    this.secretDataService = secretDataService;
    this.encryptor = encryptor;
  }

  public ResponseEntity performSet(
      AuditRecordBuilder auditRecordBuilder,
      BaseSecretSetRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry) {
    final String secretName = requestBody.getName();

    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    if (existingNamedSecret == null) { requestBody.addCurrentUser(currentUserAccessControlEntry); }

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
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private void validateSecretType(NamedSecret existingNamedSecret, String secretType) {
    if (existingNamedSecret != null && !existingNamedSecret.getSecretType().equals(secretType)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }
}
