package org.cloudfoundry.credhub.data;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.services.PermissionCheckingService;

@Component
public class CertificateAuthorityService {

  private final DefaultCertificateVersionDataService certificateVersionDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public CertificateAuthorityService(final DefaultCertificateVersionDataService certificateVersionDataService,
                                     final PermissionCheckingService permissionCheckingService,
                                     final UserContextHolder userContextHolder) {
    super();
    this.certificateVersionDataService = certificateVersionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public CertificateCredentialValue findActiveVersion(final String caName) {
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), caName, PermissionOperation.READ)) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }

    final CredentialVersion mostRecent = certificateVersionDataService.findActive(caName);

    if (mostRecent == null) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }

    if (!(mostRecent instanceof CertificateCredentialVersion)) {
      throw new ParameterizedValidationException(ErrorMessages.NOT_A_CA_NAME);
    }
    final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) mostRecent;

    if (!certificateCredential.getParsedCertificate().isCa()) {
      throw new ParameterizedValidationException(ErrorMessages.CERT_NOT_CA);
    }

    return new CertificateCredentialValue(null, certificateCredential.getCertificate(),
      certificateCredential.getPrivateKey(), null, certificateCredential.isVersionTransitional());
  }
}
