package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class PermissionedCertificateService {

  private final PermissionedCredentialService permissionedCredentialService;
  private final CertificateDataService certificateDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public PermissionedCertificateService(
      PermissionedCredentialService permissionedCredentialService, CertificateDataService certificateDataService,
      PermissionCheckingService permissionCheckingService, UserContextHolder userContextHolder) {
    this.permissionedCredentialService = permissionedCredentialService;
    this.certificateDataService = certificateDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
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
}
