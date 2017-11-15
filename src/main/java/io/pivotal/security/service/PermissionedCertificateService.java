package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.PermissionEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PermissionedCertificateService {

  private final PermissionedCredentialService permissionedCredentialService;

  @Autowired
  public PermissionedCertificateService(
      PermissionedCredentialService permissionedCredentialService) {
    this.permissionedCredentialService = permissionedCredentialService;
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
}
