package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateDataService;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.PermissionEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.request.PermissionOperation.READ;

@Service
public class PermissionedCertificateService {

  private final PermissionedCredentialService permissionedCredentialService;
  private final CertificateDataService certificateDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public PermissionedCertificateService(
      PermissionedCredentialService permissionedCredentialService, CertificateDataService certificateDataService, PermissionCheckingService permissionCheckingService, UserContextHolder userContextHolder) {
    this.permissionedCredentialService = permissionedCredentialService;
    this.certificateDataService = certificateDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public CredentialVersion save(
      CredentialVersion existingCredentialVersion, String credentialName,
      CertificateCredentialValue credentialValue,
      GenerationParameters generationParameters,
      List<PermissionEntry> accessControlEntries,
      String overwriteMode,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    if (credentialValue.isTransitional()) {

      List<CredentialVersion> credentialVersions = permissionedCredentialService
          .findAllByName(credentialName, auditRecordParameters);

      boolean transitionalVersionsAlreadyExist = credentialVersions.stream()
          .map(version -> (CertificateCredentialVersion) version)
          .anyMatch(version -> version.isVersionTransitional());

      if (transitionalVersionsAlreadyExist) {
        throw new ParameterizedValidationException("error.too_many_transitional_versions");
      }
    }
    return permissionedCredentialService.save(
        existingCredentialVersion,
        credentialName,
        "certificate",
        credentialValue,
        generationParameters,
        accessControlEntries,
        overwriteMode,
        auditRecordParameters);
  }

  public List<Credential> getAll(List<EventAuditRecordParameters> auditRecordParameters){
    auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_FIND, null));

    final List<Credential> allCertificates = certificateDataService.findAll();

    return allCertificates.stream().filter(credential ->
        permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credential.getName(), READ)
    ).collect(Collectors.toList());
  }
}
