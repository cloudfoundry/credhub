package io.pivotal.security.data;

import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.PermissionCheckingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static io.pivotal.security.request.PermissionOperation.READ;

@Component
public class CertificateAuthorityService {

  private final CertificateVersionDataService certificateVersionDataService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;

  @Autowired
  public CertificateAuthorityService(CertificateVersionDataService certificateVersionDataService,
      PermissionCheckingService permissionCheckingService,
      UserContextHolder userContextHolder) {
    this.certificateVersionDataService = certificateVersionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public CertificateCredentialValue findActiveVersion(String caName) {
    if(!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), caName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    CredentialVersion mostRecent = certificateVersionDataService.findActive(caName);

    if (mostRecent == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!(mostRecent instanceof CertificateCredentialVersion)) {
      throw new ParameterizedValidationException("error.not_a_ca_name");
    }
    CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) mostRecent;

    if (!certificateCredential.getParsedCertificate().isCa()) {
      throw new ParameterizedValidationException("error.cert_not_ca");
    }

    return new CertificateCredentialValue(null, certificateCredential.getCertificate(),
        certificateCredential.getPrivateKey(), null, certificateCredential.isVersionTransitional());
  }
}
