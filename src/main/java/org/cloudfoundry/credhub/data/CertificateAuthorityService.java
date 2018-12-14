package org.cloudfoundry.credhub.data;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.service.PermissionCheckingService;

@Component
public class CertificateAuthorityService {

  private final CertificateVersionDataService certificateVersionDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public CertificateAuthorityService(final CertificateVersionDataService certificateVersionDataService,
                                     final PermissionCheckingService permissionCheckingService,
                                     final UserContextHolder userContextHolder) {
    super();
    this.certificateVersionDataService = certificateVersionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public CertificateCredentialValue findActiveVersion(final String caName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), caName, PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    final CredentialVersion mostRecent = certificateVersionDataService.findActive(caName);

    if (mostRecent == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!(mostRecent instanceof CertificateCredentialVersion)) {
      throw new ParameterizedValidationException("error.not_a_ca_name");
    }
    final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) mostRecent;

    if (!certificateCredential.getParsedCertificate().isCa()) {
      throw new ParameterizedValidationException("error.cert_not_ca");
    }

    return new CertificateCredentialValue(null, certificateCredential.getCertificate(),
      certificateCredential.getPrivateKey(), null, certificateCredential.isVersionTransitional());
  }
}
