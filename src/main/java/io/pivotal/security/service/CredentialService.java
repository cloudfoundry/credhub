package io.pivotal.security.service;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;

@Service
public class CredentialService {

  private final CredentialDataService credentialDataService;
  private final PermissionsDataService permissionsDataService;
  private PermissionService permissionService;
  private final CredentialFactory credentialFactory;

  @Autowired
  public CredentialService(
      CredentialDataService credentialDataService,
      PermissionsDataService permissionsDataService,
      PermissionService permissionService,
      CredentialFactory credentialFactory
  ) {
    this.credentialDataService = credentialDataService;
    this.permissionsDataService = permissionsDataService;
    this.permissionService = permissionService;
    this.credentialFactory = credentialFactory;
  }

  public CredentialView save(
      String credentialName,
      String type,
      CredentialValue credentialValue,
      GenerationParameters generationParameters,
      List<PermissionEntry> accessControlEntries,
      boolean isOverwrite,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    Credential existingCredential = credentialDataService.findMostRecent(credentialName);

    boolean shouldWriteNewEntity = existingCredential == null || isOverwrite;

    AuditingOperationCode credentialOperationCode =
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    auditRecordParameters
        .add(new EventAuditRecordParameters(credentialOperationCode, credentialName));

    if (existingCredential != null) {
      verifyCredentialWritePermission(userContext, credentialName);
    }

    if (existingCredential != null && accessControlEntries.size() > 0) {
      verifyAclWrite(userContext, credentialName);
    }

    if (existingCredential != null && !existingCredential.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }

    for (PermissionEntry accessControlEntry : accessControlEntries) {
      if (!permissionService.validAclUpdateOperation(userContext, accessControlEntry.getActor())) {
        throw new InvalidAclOperationException("error.acl.invalid_update_operation");
      }
    }

    Credential storedCredentialVersion = existingCredential;
    if (shouldWriteNewEntity) {
      if (existingCredential == null) {
        accessControlEntries.add(currentUserPermissionEntry);
      }

      Credential newVersion = credentialFactory.makeNewCredentialVersion(
          CredentialType.valueOf(type),
          credentialName,
          credentialValue,
          existingCredential,
          generationParameters);
      storedCredentialVersion = credentialDataService.save(newVersion);

      permissionsDataService.saveAccessControlEntries(
          storedCredentialVersion.getCredentialName(),
          accessControlEntries);
      auditRecordParameters.addAll(createPermissionsEventAuditParameters(
          ACL_UPDATE,
          storedCredentialVersion.getName(),
          accessControlEntries
      ));
    }

    return CredentialView.fromEntity(storedCredentialVersion);
  }

  private void verifyCredentialWritePermission(UserContext userContext, String credentialName) {
    if (!permissionService.hasPermission(userContext.getAclUser(), credentialName, WRITE)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }

  private void verifyAclWrite(UserContext userContext, String credentialName) {
    if (!permissionService.hasPermission(userContext.getAclUser(), credentialName, WRITE_ACL)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }
}
