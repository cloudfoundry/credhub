package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateDataService;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
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

  @Autowired
  public PermissionedCertificateService(
      PermissionedCredentialService permissionedCredentialService, CertificateDataService certificateDataService,
      PermissionCheckingService permissionCheckingService, UserContextHolder userContextHolder, CertificateVersionDataService certificateVersionDataService) {
    this.permissionedCredentialService = permissionedCredentialService;
    this.certificateDataService = certificateDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
    this.certificateVersionDataService = certificateVersionDataService;
  }

  public CredentialVersion save(
      CredentialVersion existingCredentialVersion,
      CertificateCredentialValue credentialValue,
      BaseCredentialGenerateRequest generateRequest,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    generateRequest.setType("certificate");
    if (credentialValue.isTransitional()) {
      List<CredentialVersion> credentialVersions = permissionedCredentialService
          .findAllByName(generateRequest.getName(), auditRecordParameters);

      boolean transitionalVersionsAlreadyExist = credentialVersions.stream()
          .map(version -> (CertificateCredentialVersion) version)
          .anyMatch(version -> version.isVersionTransitional());

      if (transitionalVersionsAlreadyExist) {
        throw new ParameterizedValidationException("error.too_many_transitional_versions");
      }
    }
    return permissionedCredentialService.save(existingCredentialVersion, credentialValue, generateRequest, auditRecordParameters);
  }

  public List<Credential> getAll(List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_FIND, null));

    final List<Credential> allCertificates = certificateDataService.findAll();

    return allCertificates.stream().filter(credential ->
        permissionCheckingService
            .hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(), PermissionOperation.READ)
    ).collect(Collectors.toList());
  }

  public List<Credential> getByName(String name, List<EventAuditRecordParameters> auditRecordParameters) {
    auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_FIND, name));

    final Credential certificate = certificateDataService.findByName(name);

    if (certificate == null || !permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(), PermissionOperation.READ)) {
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
        Credential credential = permissionedCredentialService.findByUuid(uuid, auditRecordParameters);
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

  public CertificateCredentialVersion deleteVersion(UUID certificateUuid, UUID versionUuid,
                                                    List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_DELETE, null);
    auditRecordParameters.add(eventAuditRecordParameters);
    Credential certificate = certificateDataService.findByUuid(certificateUuid);
    if (certificate == null || !permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(), PermissionOperation.DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    eventAuditRecordParameters.setCredentialName(certificate.getName());
    CertificateCredentialVersion versionToDelete = certificateVersionDataService.findVersion(versionUuid);
    if (versionBelongsToCertificate(certificate, versionToDelete)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (certificateHasOnlyOneVersion(certificateUuid)) {
      throw new ParameterizedValidationException("error.credential.cannot_delete_last_version");
    }

    certificateVersionDataService.deleteVersion(versionUuid);
    return versionToDelete;
  }

  private boolean versionBelongsToCertificate(Credential certificate, CertificateCredentialVersion versionToDelete) {
    return versionToDelete == null || !certificate.getUuid().equals(versionToDelete.getCredential().getUuid());
  }

  private boolean certificateHasOnlyOneVersion(UUID certificateUuid) {
    return certificateVersionDataService.findAllVersions(certificateUuid).size() == 1;
  }
}
