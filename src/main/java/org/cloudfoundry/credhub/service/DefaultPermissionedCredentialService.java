package org.cloudfoundry.credhub.service;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.GetCredentialById;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.data.CredentialDataService;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.BaseCredentialRequest;
import org.cloudfoundry.credhub.request.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.view.FindCredentialResult;

import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;

@Service
@SuppressWarnings("PMD.TooManyMethods")
public class DefaultPermissionedCredentialService implements PermissionedCredentialService {

  private final CredentialVersionDataService credentialVersionDataService;

  private final CredentialFactory credentialFactory;
  private final CertificateAuthorityService certificateAuthorityService;
  private final UserContextHolder userContextHolder;
  private final CredentialDataService credentialDataService;
  private final CEFAuditRecord auditRecord;
  private final PermissionCheckingService permissionCheckingService;

  @Autowired
  public DefaultPermissionedCredentialService(
    final CredentialVersionDataService credentialVersionDataService,
    final CredentialFactory credentialFactory,
    final PermissionCheckingService permissionCheckingService,
    final CertificateAuthorityService certificateAuthorityService,
    final UserContextHolder userContextHolder,
    final CredentialDataService credentialDataService,
    final CEFAuditRecord auditRecord
  ) {
    super();
    this.credentialVersionDataService = credentialVersionDataService;
    this.credentialFactory = credentialFactory;
    this.permissionCheckingService = permissionCheckingService;
    this.certificateAuthorityService = certificateAuthorityService;
    this.userContextHolder = userContextHolder;
    this.credentialDataService = credentialDataService;
    this.auditRecord = auditRecord;
  }

  @Override
  public CredentialVersion save(
    final CredentialVersion existingCredentialVersion,
    final CredentialValue credentialValue,
    final BaseCredentialRequest generateRequest
  ) {
    final boolean shouldWriteNewCredential = shouldWriteNewCredential(existingCredentialVersion, generateRequest);

    validateCredentialSave(generateRequest.getName(), generateRequest.getType(), existingCredentialVersion);

    if (!shouldWriteNewCredential) {
      return existingCredentialVersion;
    }

    return makeAndSaveNewCredential(existingCredentialVersion, credentialValue, generateRequest);
  }

  @Override
  public boolean delete(final String credentialName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersionDataService.delete(credentialName);
  }

  @Override
  public List<CredentialVersion> findAllByName(final String credentialName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    final List<CredentialVersion> credentialList = credentialVersionDataService.findAllByName(credentialName);

    for (final CredentialVersion credentialVersion : credentialList) {
      auditRecord.addVersion(credentialVersion);
      auditRecord.addResource(credentialVersion.getCredential());
    }

    return credentialList;
  }

  @Override
  public List<CredentialVersion> findNByName(final String credentialName, final int numberOfVersions) {
    if (numberOfVersions < 0) {
      throw new InvalidQueryParameterException("error.invalid_query_parameter", "versions");
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findNByName(credentialName, numberOfVersions);
  }

  @Override
  public List<CredentialVersion> findActiveByName(final String credentialName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    final List<CredentialVersion> credentialList = credentialVersionDataService.findActiveByName(credentialName);

    for (final CredentialVersion credentialVersion : credentialList) {
      auditRecord.addVersion(credentialVersion);
      auditRecord.addResource(credentialVersion.getCredential());
    }

    return credentialList;
  }

  @Override
  public Credential findByUuid(final UUID credentialUUID) {
    final Credential credential = credentialDataService.findByUUID(credentialUUID);
    if (credential == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(), READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credential;
  }

  @Override
  public CredentialVersion findVersionByUuid(final String credentialUUID) {
    final CredentialVersion credentialVersion = credentialVersionDataService.findByUuid(credentialUUID);

    auditRecord.setRequestDetails(new GetCredentialById(credentialUUID));

    if (credentialVersion != null) {
      auditRecord.setVersion(credentialVersion);
      auditRecord.setResource(credentialVersion.getCredential());
    } else {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    final String credentialName = credentialVersion.getName();

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentialVersionDataService.findByUuid(credentialUUID);
  }

  @Override
  public List<String> findAllCertificateCredentialsByCaName(final String caName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), caName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentialVersionDataService.findAllCertificateCredentialsByCaName(caName);
  }

  public List<FindCredentialResult> findStartingWithPath(final String path) {
    return findStartingWithPath(path, "");
  }

  @Override
  public List<FindCredentialResult> findStartingWithPath(final String path, final String expiresWithinDays) {
    return credentialVersionDataService.findStartingWithPath(path, expiresWithinDays);
  }

  @Override
  public List<FindCredentialResult> findContainingName(final String name, final String expiresWithinDays) {
    return credentialVersionDataService.findContainingName(name, expiresWithinDays);
  }

  @Override
  public CredentialVersion findMostRecent(final String credentialName) {
    return credentialVersionDataService.findMostRecent(credentialName);
  }

  private CredentialVersion makeAndSaveNewCredential(
    final CredentialVersion existingCredentialVersion,
    final CredentialValue credentialValue,
    final BaseCredentialRequest request
  ) {
    final CredentialVersion newVersion = credentialFactory.makeNewCredentialVersion(
      CredentialType.valueOf(request.getType().toUpperCase()),
      request.getName(),
      credentialValue,
      existingCredentialVersion,
      request.getGenerationParameters()
    );
    return credentialVersionDataService.save(newVersion);
  }

  @SuppressWarnings("PMD.NPathComplexity")
  private boolean shouldWriteNewCredential(
    final CredentialVersion existingCredentialVersion, final BaseCredentialRequest request) {
    if (request instanceof BaseCredentialSetRequest) {
      return true;
    }

    if (existingCredentialVersion == null) {
      return true;
    }

    if (request instanceof BaseCredentialGenerateRequest) {
      final BaseCredentialGenerateRequest generateRequest = (BaseCredentialGenerateRequest) request;

      if (generateRequest.getMode() != null && generateRequest.getMode().equals(CredentialWriteMode.NO_OVERWRITE)) {
        return false;
      }

      if (generateRequest.getMode() != null && generateRequest.getMode().equals(CredentialWriteMode.OVERWRITE)) {
        return true;
      }
    }

    if (existingCredentialVersion instanceof CertificateCredentialVersion) {
      final CertificateCredentialVersion certificateCredentialVersion = (CertificateCredentialVersion) existingCredentialVersion;
      if (certificateCredentialVersion.getCaName() != null) {
        final boolean updatedCA = !certificateCredentialVersion.getCa().equals(
          certificateAuthorityService.findActiveVersion(certificateCredentialVersion.getCaName()).getCertificate());
        if (updatedCA) {
          return true;
        }
      }
    }

    if (!existingCredentialVersion.matchesGenerationParameters(request.getGenerationParameters())) {
      return true;
    }


    final BaseCredentialGenerateRequest generateRequest = (BaseCredentialGenerateRequest) request;
    return generateRequest.isOverwrite();

  }

  private void validateCredentialSave(final String credentialName, final String type, final CredentialVersion existingCredentialVersion) {
    verifyWritePermission(credentialName);

    if (existingCredentialVersion != null && !existingCredentialVersion.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }

  private void verifyWritePermission(final String credentialName) {
    if (userContextHolder.getUserContext() == null) {
      return;
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialName, WRITE)) {
      throw new PermissionException("error.credential.invalid_access");
    }
  }
}
