package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.service.PermissionCheckingService;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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
    if(!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), caName, PermissionOperation.READ)) {
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
