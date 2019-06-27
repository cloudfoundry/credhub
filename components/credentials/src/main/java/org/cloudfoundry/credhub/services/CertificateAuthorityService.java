package org.cloudfoundry.credhub.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

@Component
public class CertificateAuthorityService {

  private final DefaultCertificateVersionDataService certificateVersionDataService;

  @Autowired
  public CertificateAuthorityService(final DefaultCertificateVersionDataService certificateVersionDataService) {
    super();
    this.certificateVersionDataService = certificateVersionDataService;
  }

  public CertificateCredentialValue findActiveVersion(final String caName) {
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

    return new CertificateCredentialValue(
            null,
            certificateCredential.getCertificate(),
            certificateCredential.getPrivateKey(),
            null,
            certificateCredential.isCertificateAuthority(),
            certificateCredential.isSelfSigned(),
            certificateCredential.getGenerated(),
            certificateCredential.isVersionTransitional());
  }
}
