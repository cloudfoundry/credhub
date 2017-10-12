package io.pivotal.security.service;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.view.FindCredentialResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;

@Service
public class PermissionedCredentialService {
  private final CredentialVersionDataService credentialVersionDataService;

  private PermissionService permissionService;
  private final CredentialFactory credentialFactory;
  private PermissionCheckingService permissionCheckingService;

  @Autowired
  public PermissionedCredentialService(
      CredentialVersionDataService credentialVersionDataService,
      PermissionService permissionService,
      CredentialFactory credentialFactory,
      PermissionCheckingService permissionCheckingService) {
    this.credentialVersionDataService = credentialVersionDataService;
    this.permissionService = permissionService;
    this.credentialFactory = credentialFactory;
    this.permissionCheckingService = permissionCheckingService;
  }

  public CredentialVersion save(
      CredentialVersion existingCredentialVersion, String credentialName,
      String type,
      CredentialValue credentialValue,
      GenerationParameters generationParameters,
      List<PermissionEntry> accessControlEntries,
      String overwriteMode,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {

    final boolean isNewCredential = existingCredentialVersion == null;

    boolean shouldWriteNewCredential;
    if ("converge".equals(overwriteMode)) {
      StringGenerationParameters existingGenerationParameters = existingCredentialVersion
          .getGenerationParameters();

      StringGenerationParameters newGenerationParameters = (StringGenerationParameters) generationParameters;
      shouldWriteNewCredential = !(newGenerationParameters.equals(existingGenerationParameters));
    } else {
     shouldWriteNewCredential = isNewCredential || "overwrite".equals(overwriteMode);
    }

    writeSaveAuditRecord(credentialName, auditRecordParameters, shouldWriteNewCredential);

    validateCredentialSave(credentialName, type, accessControlEntries, userContext, existingCredentialVersion);

    if (!shouldWriteNewCredential) {
      return existingCredentialVersion;
    }

    return makeAndSaveNewCredential(
        credentialName,
        type,
        credentialValue,
        generationParameters,
        existingCredentialVersion
    );
  }

  public boolean delete(UserContext userContext, String credentialName, List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_DELETE, credentialName));
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersionDataService.delete(credentialName);
  }

  public List<CredentialVersion> findAllByName(UserContext userContext, String credentialName, List<EventAuditRecordParameters> auditRecordParametersList) {
    auditRecordParametersList.add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credentialName));

    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findAllByName(credentialName);
  }

  public List<CredentialVersion> findNByName(UserContext userContext, String credentialName, Integer numberOfVersions, List<EventAuditRecordParameters> auditRecordParametersList) {
    auditRecordParametersList.add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credentialName));

    if (numberOfVersions < 0) {
      throw new InvalidQueryParameterException("error.invalid_query_parameter", "versions");
    }

    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findNByName(credentialName, numberOfVersions);
  }

  public CredentialVersion findByUuid(UserContext userContext, String credentialUUID, List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_ACCESS
    );
    auditRecordParameters.add(eventAuditRecordParameters);

    CredentialVersion credentialVersion = credentialVersionDataService.findByUuid(credentialUUID);
    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    String credentialName = credentialVersion.getName();
    eventAuditRecordParameters.setCredentialName(credentialName);

    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersionDataService.findByUuid(credentialUUID);
  }

  public List<String> findAllCertificateCredentialsByCaName(UserContext userContext, String caName) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), caName, PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findAllCertificateCredentialsByCaName(caName);
  }

  public List<FindCredentialResult> findStartingWithPath(String path, List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_FIND));
    return credentialVersionDataService.findStartingWithPath(path);
  }

  public List<String> findAllPaths(List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_FIND));
    return credentialVersionDataService.findAllPaths();
  }

  public List<FindCredentialResult> findContainingName(String name, List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_FIND));
    return credentialVersionDataService.findContainingName(name);
  }

  public CredentialVersion findMostRecent(String credentialName) {
    return credentialVersionDataService.findMostRecent(credentialName);
  }

  private CredentialVersion makeAndSaveNewCredential(String credentialName, String type, CredentialValue credentialValue, GenerationParameters generationParameters, CredentialVersion existingCredentialVersion) {
    CredentialVersion newVersion = credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf(type),
        credentialName,
        credentialValue,
        existingCredentialVersion,
        generationParameters);
    return credentialVersionDataService.save(newVersion);
  }

  private void validateCredentialSave(String credentialName, String type, List<PermissionEntry> accessControlEntries, UserContext userContext, CredentialVersion existingCredentialVersion) {
    if (existingCredentialVersion != null) {
      verifyCredentialWritePermission(userContext, credentialName);
    }

    if (existingCredentialVersion != null && accessControlEntries.size() > 0) {
      verifyAclWrite(userContext, credentialName);
    }

    if (existingCredentialVersion != null && !existingCredentialVersion.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }

  private void writeSaveAuditRecord(String credentialName, List<EventAuditRecordParameters> auditRecordParameters, boolean shouldWriteNewEntity) {
    AuditingOperationCode credentialOperationCode =
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    auditRecordParameters
        .add(new EventAuditRecordParameters(credentialOperationCode, credentialName));
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
}
