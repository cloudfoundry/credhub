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
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.FindCredentialResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;

@Service
public class PermissionedCredentialService {

  private final CredentialDataService credentialDataService;
  private final PermissionsDataService permissionsDataService;
  private PermissionService permissionService;
  private final CredentialFactory credentialFactory;
  private PermissionCheckingService permissionCheckingService;

  @Autowired
  public PermissionedCredentialService(
      CredentialDataService credentialDataService,
      PermissionsDataService permissionsDataService,
      PermissionService permissionService,
      CredentialFactory credentialFactory,
      PermissionCheckingService permissionCheckingService) {
    this.credentialDataService = credentialDataService;
    this.permissionsDataService = permissionsDataService;
    this.permissionService = permissionService;
    this.credentialFactory = credentialFactory;
    this.permissionCheckingService = permissionCheckingService;
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
      if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, accessControlEntry.getActor())) {
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
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, WRITE)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }

  private void verifyAclWrite(UserContext userContext, String credentialName) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, WRITE_ACL)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }

  public boolean delete(UserContext userContext, String credentialName) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialDataService.delete(credentialName);
  }

  public List<Credential> findAllByName(UserContext userContext, String credentialName) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialDataService.findAllByName(credentialName);
  }

  public List<Credential> findNByName(UserContext userContext, String credentialName, Integer numberOfVersions) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialDataService.findNByName(credentialName, numberOfVersions);
  }

  public Credential findByUuid(UserContext userContext, String credentialUUID, List<EventAuditRecordParameters> auditRecordParametersList) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_ACCESS
    );
    auditRecordParametersList.add(eventAuditRecordParameters);

    Credential credential = credentialDataService.findByUuid(credentialUUID);
    if (credential == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    String credentialName = credential.getName();
    eventAuditRecordParameters.setCredentialName(credentialName);

    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialDataService.findByUuid(credentialUUID);
  }

  public List<String> findAllCertificateCredentialsByCaName(UserContext userContext, String caName) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), caName, PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialDataService.findAllCertificateCredentialsByCaName(caName);
  }

  public List<FindCredentialResult> findStartingWithPath(String path) {
    return credentialDataService.findStartingWithPath(path);
  }

  public List<String> findAllPaths() {
    return credentialDataService.findAllPaths();
  }

  public List<FindCredentialResult> findContainingName(String name) {
    return credentialDataService.findContainingName(name);
  }

  public Credential findMostRecent(String credentialName) {
    return credentialDataService.findMostRecent(credentialName);
  }
}
