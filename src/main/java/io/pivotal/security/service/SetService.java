package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class SetService {
  private final Encryptor encryptor;
  private final CredentialDataService credentialDataService;

  @Autowired
  public SetService(CredentialDataService credentialDataService,
                    Encryptor encryptor
  ) {
    this.credentialDataService = credentialDataService;
    this.encryptor = encryptor;
  }

  public CredentialView performSet(
      EventAuditRecordParameters eventAuditRecordParameters,
      BaseCredentialSetRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry) {
    final String credentialName = requestBody.getName();

    Credential existingCredential = credentialDataService.findMostRecent(credentialName);

    if (existingCredential == null) { requestBody.addCurrentUser(currentUserAccessControlEntry); }

    boolean shouldWriteNewEntity = existingCredential == null || requestBody.isOverwrite();

    eventAuditRecordParameters.setAuditingOperationCode(shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS);

    final String type = requestBody.getType();
    validateSecretType(existingCredential, type);

    Credential storedEntity = existingCredential;
    if (shouldWriteNewEntity) {
      Credential newEntity = (Credential) requestBody.createNewVersion(existingCredential, encryptor);
      storedEntity = credentialDataService.save(newEntity);
    }
    eventAuditRecordParameters.setCredentialName(storedEntity.getName());

    return CredentialView.fromEntity(storedEntity);
  }

  private void validateSecretType(Credential existingCredential, String secretType) {
    if (existingCredential != null && !existingCredential.getSecretType().equals(secretType)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }
}
