package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
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
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class PermissionedCertificateService {

  private final PermissionedCredentialService permissionedCredentialService;
  private final CertificateDataService certificateDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;
  private final CertificateVersionDataService certificateVersionDataService;
  private final CertificateCredentialFactory certificateCredentialFactory;
  private final CredentialVersionDataService credentialVersionDataService;
  private CEFAuditRecord auditRecord;

  @Autowired
  public PermissionedCertificateService(
      PermissionedCredentialService permissionedCredentialService, CertificateDataService certificateDataService,
      PermissionCheckingService permissionCheckingService, UserContextHolder userContextHolder,
      CertificateVersionDataService certificateVersionDataService,
      CertificateCredentialFactory certificateCredentialFactory,
      CredentialVersionDataService credentialVersionDataService,
      CEFAuditRecord auditRecord) {
    this.permissionedCredentialService = permissionedCredentialService;
    this.certificateDataService = certificateDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
    this.certificateVersionDataService = certificateVersionDataService;
    this.certificateCredentialFactory = certificateCredentialFactory;
    this.credentialVersionDataService = credentialVersionDataService;
    this.auditRecord = auditRecord;
  }

  public CredentialVersion save(
      CredentialVersion existingCredentialVersion,
      CertificateCredentialValue credentialValue,
      BaseCredentialGenerateRequest generateRequest
  ) {
    generateRequest.setType("certificate");
    if (credentialValue.isTransitional()) {
      validateNoTransitionalVersionsAlreadyExist(generateRequest.getName());
    }
    return permissionedCredentialService
        .save(existingCredentialVersion, credentialValue, generateRequest);
  }

  private void validateNoTransitionalVersionsAlreadyExist(String name) {
    List<CredentialVersion> credentialVersions = permissionedCredentialService
        .findAllByName(name);

    boolean transitionalVersionsAlreadyExist = credentialVersions.stream()
        .map(version -> (CertificateCredentialVersion) version)
        .anyMatch(version -> version.isVersionTransitional());

    if (transitionalVersionsAlreadyExist) {
      throw new ParameterizedValidationException("error.too_many_transitional_versions");
    }
  }

  public List<Credential> getAll() {
    final List<Credential> allCertificates = certificateDataService.findAll();

    return allCertificates.stream().filter(credential ->
        permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(),
            PermissionOperation.READ)
    ).collect(Collectors.toList());
  }

  public List<Credential> getByName(String name) {
    final Credential certificate = certificateDataService.findByName(name);

    if (certificate == null || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(),
            PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return Collections.singletonList(certificate);
  }

  public List<CredentialVersion> getVersions(UUID uuid, boolean current) {
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
      throw new InvalidQueryParameterException("error.bad_request", "uuid");
    }

    if (list.isEmpty() || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), name, PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return list;
  }

  public List<CredentialVersion> updateTransitionalVersion(UUID certificateUuid, UUID newTransitionalVersionUuid) {
    Credential credential = findCertificateCredential(certificateUuid);

    String name = credential.getName();

    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), name, PermissionOperation.WRITE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    certificateVersionDataService.unsetTransitionalVersion(certificateUuid);

    if (newTransitionalVersionUuid != null) {
      CertificateCredentialVersion version = certificateVersionDataService.findVersion(newTransitionalVersionUuid);

      if (versionDoesNotBelongToCertificate(credential, version)) {
        throw new ParameterizedValidationException("error.credential.mismatched_credential_and_version");
      }
      certificateVersionDataService.setTransitionalVersion(newTransitionalVersionUuid);
    }

    List<CredentialVersion> credentialVersions = certificateVersionDataService.findActiveWithTransitional(name);
    auditRecord.addAllResources(credentialVersions);

    return credentialVersions;
  }

  public CertificateCredentialVersion deleteVersion(UUID certificateUuid, UUID versionUuid) {
    Credential certificate = certificateDataService.findByUuid(certificateUuid);
    if (certificate == null || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(),
            PermissionOperation.DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
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

  public CertificateCredentialVersion set(UUID certificateUuid, CertificateCredentialValue value) {
    Credential credential = findCertificateCredential(certificateUuid);

    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(),
            PermissionOperation.WRITE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (value.isTransitional()) {
      validateNoTransitionalVersionsAlreadyExist(credential.getName());
    }

    CertificateCredentialVersion certificateCredentialVersion = certificateCredentialFactory
        .makeNewCredentialVersion(credential, value);

    return credentialVersionDataService.save(certificateCredentialVersion);
  }
}
