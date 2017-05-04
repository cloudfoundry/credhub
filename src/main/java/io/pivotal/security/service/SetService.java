package io.pivotal.security.service;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;

@Service
public class SetService {
  private final CredentialDataService credentialDataService;
  private final AccessControlDataService accessControlDataService;
  private PermissionService permissionService;
  private final Encryptor encryptor;

  @Autowired
  public SetService(
      CredentialDataService credentialDataService,
      AccessControlDataService accessControlDataService,
      PermissionService permissionService,
      Encryptor encryptor
  ) {
    this.credentialDataService = credentialDataService;
    this.accessControlDataService = accessControlDataService;
    this.permissionService = permissionService;
    this.encryptor = encryptor;
  }

  public CredentialView performSet(
      UserContext userContext,
      List<EventAuditRecordParameters> parametersList,
      BaseCredentialSetRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry) {
    final String credentialName = requestBody.getName();

    Credential existingCredential = credentialDataService.findMostRecent(credentialName);

    boolean shouldWriteNewEntity = existingCredential == null || requestBody.isOverwrite();

    AuditingOperationCode credentialOperationCode =
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    parametersList.add(new EventAuditRecordParameters(credentialOperationCode, requestBody.getName()));

    if (existingCredential != null) {
      permissionService.verifyCredentialWritePermission(userContext, existingCredential.getCredentialName());
    }

    final String type = requestBody.getType();
    if (existingCredential != null && !existingCredential.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }

    List<AccessControlEntry> accessControlEntryList = requestBody.getAccessControlEntries();
    Credential storedEntity = existingCredential;

    if (shouldWriteNewEntity) {
      if (existingCredential == null) {
        accessControlEntryList.add(currentUserAccessControlEntry);
      }

      parametersList.addAll(createPermissionsEventAuditParameters(
          ACL_UPDATE,
          requestBody.getName(),
          accessControlEntryList
      ));

      Credential newEntity = (Credential) requestBody.createNewVersion(existingCredential, encryptor);
      storedEntity = credentialDataService.save(newEntity);
      accessControlDataService.setAccessControlEntries(storedEntity.getCredentialName(), accessControlEntryList);
    }

    return CredentialView.fromEntity(storedEntity);
  }
}
