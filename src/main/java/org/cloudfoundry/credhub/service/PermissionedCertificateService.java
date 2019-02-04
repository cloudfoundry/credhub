package org.cloudfoundry.credhub.service;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

@Service
@Transactional
@SuppressWarnings({
  "PMD.NullAssignment",
  "PMD.TooManyMethods",
  "PMD.NPathComplexity",
})
public class PermissionedCertificateService {

  private final PermissionedCredentialService permissionedCredentialService;
  private final CertificateDataService certificateDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;
  private final CertificateVersionDataService certificateVersionDataService;
  private final CertificateCredentialFactory certificateCredentialFactory;
  private final CredentialVersionDataService credentialVersionDataService;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public PermissionedCertificateService(
          final PermissionedCredentialService permissionedCredentialService, final CertificateDataService certificateDataService,
          final PermissionCheckingService permissionCheckingService, final UserContextHolder userContextHolder,
          final CertificateVersionDataService certificateVersionDataService,
          final CertificateCredentialFactory certificateCredentialFactory,
          final CredentialVersionDataService credentialVersionDataService,
          final CEFAuditRecord auditRecord
  ) {
    super();
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
    final CredentialVersion existingCredentialVersion,
    final CertificateCredentialValue credentialValue,
    final BaseCredentialGenerateRequest generateRequest
  ) {
    generateRequest.setType("certificate");
    if (credentialValue.isTransitional()) {
      validateNoTransitionalVersionsAlreadyExist(generateRequest.getName());
    }
    return permissionedCredentialService
      .save(existingCredentialVersion, credentialValue, generateRequest);
  }

  private void validateNoTransitionalVersionsAlreadyExist(final String name) {
    final List<CredentialVersion> credentialVersions = permissionedCredentialService
      .findAllByName(name);

    final boolean transitionalVersionsAlreadyExist = credentialVersions.stream()
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

  public List<Credential> getByName(final String name) {
    final Credential certificate = certificateDataService.findByName(name);

    if (certificate == null || !permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(),
        PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return Collections.singletonList(certificate);
  }

  public List<CredentialVersion> getVersions(final UUID uuid, final boolean current) {
    final List<CredentialVersion> list;
    final String name;

    try {
      if (current) {
        final Credential credential = findCertificateCredential(uuid);
        name = credential.getName();
        list = certificateVersionDataService.findActiveWithTransitional(name);
      } else {
        list = certificateVersionDataService.findAllVersions(uuid);
        name = !list.isEmpty() ? list.get(0).getName() : null;
      }
    } catch (final IllegalArgumentException e) {
      throw new InvalidQueryParameterException("error.bad_request", "uuid");
    }

    if (list.isEmpty() || !permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), name, PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return list;
  }

  public List<CredentialVersion> updateTransitionalVersion(final UUID certificateUuid, final UUID newTransitionalVersionUuid) {
    final Credential credential = findCertificateCredential(certificateUuid);

    final String name = credential.getName();

    if (!permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), name, PermissionOperation.WRITE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    certificateVersionDataService.unsetTransitionalVersion(certificateUuid);

    if (newTransitionalVersionUuid != null) {
      final CertificateCredentialVersion version = certificateVersionDataService.findVersion(newTransitionalVersionUuid);

      if (versionDoesNotBelongToCertificate(credential, version)) {
        throw new ParameterizedValidationException("error.credential.mismatched_credential_and_version");
      }
      certificateVersionDataService.setTransitionalVersion(newTransitionalVersionUuid);
    }

    final List<CredentialVersion> credentialVersions = certificateVersionDataService.findActiveWithTransitional(name);
    auditRecord.addAllVersions(credentialVersions);

    return credentialVersions;
  }

  public CertificateCredentialVersion deleteVersion(final UUID certificateUuid, final UUID versionUuid) {
    final Credential certificate = certificateDataService.findByUuid(certificateUuid);
    if (certificate == null || !permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(),
        PermissionOperation.DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    final CertificateCredentialVersion versionToDelete = certificateVersionDataService.findVersion(versionUuid);
    if (versionDoesNotBelongToCertificate(certificate, versionToDelete)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (certificateHasOnlyOneVersion(certificateUuid)) {
      throw new ParameterizedValidationException("error.credential.cannot_delete_last_version");
    }

    certificateVersionDataService.deleteVersion(versionUuid);
    return versionToDelete;
  }

  private boolean versionDoesNotBelongToCertificate(final Credential certificate, final CertificateCredentialVersion version) {
    return version == null || !certificate.getUuid().equals(version.getCredential().getUuid());
  }

  private boolean certificateHasOnlyOneVersion(final UUID certificateUuid) {
    return certificateVersionDataService.findAllVersions(certificateUuid).size() == 1;
  }

  private Credential findCertificateCredential(final UUID certificateUuid) {
    final Credential credential = certificateDataService.findByUuid(certificateUuid);

    if (credential == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credential;
  }

  public CertificateCredentialVersion set(final UUID certificateUuid, final CertificateCredentialValue value) {
    final Credential credential = findCertificateCredential(certificateUuid);

    if (!permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(),
        PermissionOperation.WRITE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (value.isTransitional()) {
      validateNoTransitionalVersionsAlreadyExist(credential.getName());
    }

    final CertificateCredentialVersion certificateCredentialVersion = certificateCredentialFactory
      .makeNewCredentialVersion(credential, value);

    return credentialVersionDataService.save(certificateCredentialVersion);
  }
}
