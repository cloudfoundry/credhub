package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateDataService;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialFactory;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class PermissionedCertificateService {

  private final PermissionedCredentialService permissionedCredentialService;
  private final CertificateDataService certificateDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;
  private final CertificateVersionDataService certificateVersionDataService;
  private final CertificateCredentialFactory certificateCredentialFactory;
  private final CredentialVersionDataService credentialVersionDataService;

  @Autowired
  public PermissionedCertificateService(
      PermissionedCredentialService permissionedCredentialService, CertificateDataService certificateDataService,
      PermissionCheckingService permissionCheckingService, UserContextHolder userContextHolder,
      CertificateVersionDataService certificateVersionDataService,
      CertificateCredentialFactory certificateCredentialFactory,
      CredentialVersionDataService credentialVersionDataService) {
    this.permissionedCredentialService = permissionedCredentialService;
    this.certificateDataService = certificateDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
    this.certificateVersionDataService = certificateVersionDataService;
    this.certificateCredentialFactory = certificateCredentialFactory;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  public CredentialVersion save(
      CredentialVersion existingCredentialVersion,
      CertificateCredentialValue credentialValue,
      BaseCredentialGenerateRequest generateRequest,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    generateRequest.setType("certificate");
    if (credentialValue.isTransitional()) {
      validateNoTransitionalVersionsAlreadyExist(generateRequest.getName(), auditRecordParameters);
    }
    return permissionedCredentialService
        .save(existingCredentialVersion, credentialValue, generateRequest, auditRecordParameters);
  }

  private void validateNoTransitionalVersionsAlreadyExist(String name, List<EventAuditRecordParameters> auditRecordParameters) {
    List<CredentialVersion> credentialVersions = permissionedCredentialService
        .findAllByName(name, auditRecordParameters);

    boolean transitionalVersionsAlreadyExist = credentialVersions.stream()
        .map(version -> (CertificateCredentialVersion) version)
        .anyMatch(version -> version.isVersionTransitional());

    if (transitionalVersionsAlreadyExist) {
      throw new ParameterizedValidationException("error.too_many_transitional_versions");
    }
  }

  public List<Credential> getAll(List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_FIND, null));

    final List<Credential> allCertificates = certificateDataService.findAll();

    return allCertificates.stream().filter(credential ->
        permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(),
            PermissionOperation.READ)
    ).collect(Collectors.toList());
  }

  public List<Credential> getByName(String name, List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_FIND, name));

    final Credential certificate = certificateDataService.findByName(name);

    if (certificate == null || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(),
            PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return Collections.singletonList(certificate);
  }

  public List<CredentialVersion> getVersions(UUID uuid, boolean current,
      List<EventAuditRecordParameters> auditRecordParameters) {
    List<CredentialVersion> list;
    String name;

    try {
      if (current) {
        Credential credential = findCertificateCredential(uuid);
        name = credential.getName();
        list = certificateVersionDataService.findActiveWithTransitional(name);
      } else {
        list = certificateVersionDataService.findAllVersions(uuid);
        name = !list.isEmpty() ? list.get(0).getName() : null;
      }
    } catch (IllegalArgumentException e) {
      auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS, null));
      throw new InvalidQueryParameterException("error.bad_request", "uuid");
    }

    auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS, name));

    if (list.isEmpty() || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), name, PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return list;
  }

  public List<CredentialVersion> updateTransitionalVersion(UUID certificateUuid, UUID newTransitionalVersionUuid,
      List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_UPDATE, null);
    auditRecordParameters.add(eventAuditRecordParameters);
    Credential credential = findCertificateCredential(certificateUuid);

    String name = credential.getName();
    eventAuditRecordParameters.setCredentialName(name);

    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), name, PermissionOperation.WRITE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    certificateVersionDataService.unsetTransitionalVerison(certificateUuid);

    if(newTransitionalVersionUuid != null) {
      CertificateCredentialVersion version = certificateVersionDataService.findVersion(newTransitionalVersionUuid);

      if (versionDoesNotBelongToCertificate(credential, version)) {
        throw new ParameterizedValidationException("error.credential.mismatched_credential_and_version");
      }
      certificateVersionDataService.setTransitionalVersion(newTransitionalVersionUuid);
    }
    return certificateVersionDataService.findActiveWithTransitional(name);
  }

  public CertificateCredentialVersion deleteVersion(UUID certificateUuid, UUID versionUuid,
      List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_DELETE, null);
    auditRecordParameters.add(eventAuditRecordParameters);
    Credential certificate = certificateDataService.findByUuid(certificateUuid);
    if (certificate == null || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(),
            PermissionOperation.DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    eventAuditRecordParameters.setCredentialName(certificate.getName());
    CertificateCredentialVersion versionToDelete = certificateVersionDataService.findVersion(versionUuid);
    if (versionDoesNotBelongToCertificate(certificate, versionToDelete)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (certificateHasOnlyOneVersion(certificateUuid)) {
      throw new ParameterizedValidationException("error.credential.cannot_delete_last_version");
    }

    certificateVersionDataService.deleteVersion(versionUuid);
    return versionToDelete;
  }

  private boolean versionDoesNotBelongToCertificate(Credential certificate, CertificateCredentialVersion version) {
    return version == null || !certificate.getUuid().equals(version.getCredential().getUuid());
  }

  private boolean certificateHasOnlyOneVersion(UUID certificateUuid) {
    return certificateVersionDataService.findAllVersions(certificateUuid).size() == 1;
  }

  private Credential findCertificateCredential(UUID certificateUuid) {
    Credential credential = certificateDataService.findByUuid(certificateUuid);

    if (credential == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credential;
  }

  public CertificateCredentialVersion set(UUID certificateUuid, CertificateCredentialValue value,
      List<EventAuditRecordParameters> auditRecordParameters) {
    Credential credential = findCertificateCredential(certificateUuid);

    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_UPDATE, credential.getName());
    auditRecordParameters.add(eventAuditRecordParameters);

    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(),
            PermissionOperation.WRITE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (value.isTransitional()) {
      validateNoTransitionalVersionsAlreadyExist(credential.getName(), auditRecordParameters);
    }

    CertificateCredentialVersion certificateCredentialVersion = certificateCredentialFactory
        .makeNewCredentialVersion(credential, value);

    return credentialVersionDataService.save(certificateCredentialVersion);
  }
}
