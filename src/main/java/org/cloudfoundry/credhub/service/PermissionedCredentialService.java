package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.request.BaseCredentialRequest;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.view.FindCredentialResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_DELETE;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;

@Service
public class PermissionedCredentialService {
  private final CredentialVersionDataService credentialVersionDataService;

  private final CredentialFactory credentialFactory;
  private final CertificateAuthorityService certificateAuthorityService;
  private PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public PermissionedCredentialService(
      CredentialVersionDataService credentialVersionDataService,
      CredentialFactory credentialFactory,
      PermissionCheckingService permissionCheckingService,
      CertificateAuthorityService certificateAuthorityService,
      UserContextHolder userContextHolder) {
    this.credentialVersionDataService = credentialVersionDataService;
    this.credentialFactory = credentialFactory;
    this.permissionCheckingService = permissionCheckingService;
    this.certificateAuthorityService = certificateAuthorityService;
    this.userContextHolder = userContextHolder;
  }

  public CredentialVersion save(
      CredentialVersion existingCredentialVersion,
      CredentialValue credentialValue,
      BaseCredentialRequest generateRequest,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {

    List<PermissionEntry> accessControlEntries = generateRequest.getAdditionalPermissions();
    boolean shouldWriteNewCredential = shouldWriteNewCredential(existingCredentialVersion, generateRequest);

    writeSaveAuditRecord(generateRequest.getName(), auditRecordParameters, shouldWriteNewCredential);
    validateCredentialSave(generateRequest.getName(), generateRequest.getType(), accessControlEntries, existingCredentialVersion);

    if (!shouldWriteNewCredential) {
      return existingCredentialVersion;
    }

    return makeAndSaveNewCredential(existingCredentialVersion, credentialValue, generateRequest);
  }

  public boolean delete(String credentialName, List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_DELETE, credentialName));
    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersionDataService.delete(credentialName);
  }

  public List<CredentialVersion> findAllByName(String credentialName, List<EventAuditRecordParameters> auditRecordParametersList) {
    auditRecordParametersList.add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credentialName));

    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findAllByName(credentialName);
  }

  public List<CredentialVersion> findNByName(String credentialName, Integer numberOfVersions, List<EventAuditRecordParameters> auditRecordParametersList) {
    auditRecordParametersList.add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credentialName));

    if (numberOfVersions < 0) {
      throw new InvalidQueryParameterException("error.invalid_query_parameter", "versions");
    }

    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findNByName(credentialName, numberOfVersions);
  }

  public CredentialVersion findByUuid(String credentialUUID, List<EventAuditRecordParameters> auditRecordParameters) {
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
        .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersionDataService.findByUuid(credentialUUID);
  }

  public List<String> findAllCertificateCredentialsByCaName(String caName) {
    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), caName, PermissionOperation.READ)) {
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

  private CredentialVersion makeAndSaveNewCredential(CredentialVersion existingCredentialVersion, CredentialValue credentialValue, BaseCredentialRequest request) {
    CredentialVersion newVersion = credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf(request.getType()),
        request.getName(),
        credentialValue,
        existingCredentialVersion,
        request.getGenerationParameters());
    return credentialVersionDataService.save(newVersion);
  }

  private boolean shouldWriteNewCredential(CredentialVersion existingCredentialVersion, BaseCredentialRequest request) {
    boolean shouldWriteNewCredential;
    if (existingCredentialVersion == null) {
      shouldWriteNewCredential = true;
    } else if (request.getOverwriteMode().equals(CredentialWriteMode.CONVERGE.mode)) {
      if (existingCredentialVersion instanceof CertificateCredentialVersion) {
        final CertificateCredentialVersion certificateCredentialVersion = (CertificateCredentialVersion) existingCredentialVersion;
        if (certificateCredentialVersion.getCaName() != null) {
          boolean updatedCA = !certificateCredentialVersion.getCa().equals(certificateAuthorityService.findActiveVersion(certificateCredentialVersion.getCaName()).getCertificate());
          if (updatedCA) {
            return true;
          }
        }
      }
      shouldWriteNewCredential = !existingCredentialVersion.matchesGenerationParameters(request.getGenerationParameters());
    } else {
      shouldWriteNewCredential = request.getOverwriteMode().equals(CredentialWriteMode.OVERWRITE.mode);
    }
    return shouldWriteNewCredential;
  }

  private void validateCredentialSave(String credentialName, String type, List<PermissionEntry> accessControlEntries, CredentialVersion existingCredentialVersion) {
    if (existingCredentialVersion != null) {
      verifyCredentialWritePermission(credentialName);
    }

    if (existingCredentialVersion != null && accessControlEntries.size() > 0) {
      verifyWritePermission(credentialName);
    }

    if (existingCredentialVersion != null && !existingCredentialVersion.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }

  private void writeSaveAuditRecord(String credentialName, List<EventAuditRecordParameters> auditRecordParameters, boolean shouldWriteNewEntity) {
    AuditingOperationCode credentialOperationCode = shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    auditRecordParameters.add(new EventAuditRecordParameters(credentialOperationCode, credentialName));
  }

  private void verifyCredentialWritePermission(String credentialName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, WRITE)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }

  private void verifyWritePermission(String credentialName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, WRITE_ACL)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }
}
