package io.pivotal.security.service;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.view.CredentialView;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SetService {
  private final CredentialDataService credentialDataService;
  private final AccessControlDataService accessControlDataService;
  private final Encryptor encryptor;

  @Autowired
  public SetService(
      CredentialDataService credentialDataService,
      AccessControlDataService accessControlDataService,
      Encryptor encryptor
  ) {
    this.credentialDataService = credentialDataService;
    this.accessControlDataService = accessControlDataService;
    this.encryptor = encryptor;
  }

  public CredentialView performSet(
      List<EventAuditRecordParameters> parametersList,
      BaseCredentialSetRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry) {
    final String credentialName = requestBody.getName();

    Credential existingCredential = credentialDataService.findMostRecent(credentialName);

    boolean shouldWriteNewEntity = existingCredential == null || requestBody.isOverwrite();

    AuditingOperationCode credentialOperationCode =
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    final String type = requestBody.getType();

    if (existingCredential != null && !existingCredential.getCredentialType().equals(type)) {
      parametersList.add(new EventAuditRecordParameters(credentialOperationCode, existingCredential.getName()));
      throw new ParameterizedValidationException("error.type_mismatch");
    }

    Credential storedEntity = existingCredential;
    if (shouldWriteNewEntity) {
      Credential newEntity = (Credential) requestBody.createNewVersion(existingCredential, encryptor);
      storedEntity = credentialDataService.save(newEntity);
    }
    parametersList.add(new EventAuditRecordParameters(credentialOperationCode, storedEntity.getName()));


    List<AccessControlEntry> accessControlEntryList = requestBody.getAccessControlEntries();

    if (existingCredential == null) {
      accessControlEntryList.add(currentUserAccessControlEntry);
    }

    final String name = storedEntity.getName();

    if (shouldWriteNewEntity) {
      accessControlEntryList.stream()
          .forEach(entry -> {
            String actor = entry.getActor();
            entry.getAllowedOperations().stream()
                .forEach(operation -> {
                  parametersList.add(new EventAuditRecordParameters(
                      ACL_UPDATE,
                      name,
                      operation,
                      actor));
                });
          });

      accessControlDataService.setAccessControlEntries(storedEntity.getCredentialName(), requestBody.getAccessControlEntries());
    }

    return CredentialView.fromEntity(storedEntity);
  }
}
