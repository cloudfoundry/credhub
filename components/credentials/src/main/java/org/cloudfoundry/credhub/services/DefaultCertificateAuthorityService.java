package org.cloudfoundry.credhub.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

@Component
@Profile("!remote")
public class DefaultCertificateAuthorityService implements CertificateAuthorityService {

  private final DefaultCertificateVersionDataService certificateVersionDataService;

  @Autowired
  public DefaultCertificateAuthorityService(final DefaultCertificateVersionDataService certificateVersionDataService) {
    super();
    this.certificateVersionDataService = certificateVersionDataService;
  }

  @Override
  public CertificateCredentialValue findActiveVersion(final String caName) {
    final CredentialVersion mostRecent = certificateVersionDataService.findActive(caName);

    if (mostRecent == null) {
      throw new EntryNotFoundException(ErrorMessages.Credential.CERTIFICATE_ACCESS);
    }

    if (!(mostRecent instanceof CertificateCredentialVersion)) {
      throw new ParameterizedValidationException(ErrorMessages.NOT_A_CA_NAME);
    }
    final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) mostRecent;

    if (!certificateCredential.getParsedCertificate().isCa()) {
      throw new ParameterizedValidationException(ErrorMessages.CERT_NOT_CA);
    }
    return new CertificateCredentialValue(
            certificateCredential.getCertificate(),
            certificateCredential.getPrivateKey(),
            certificateCredential.isCertificateAuthority(),
            certificateCredential.isSelfSigned(),
            certificateCredential.getGenerated(),
            certificateCredential.isVersionTransitional(),
            certificateCredential.getVersionCreatedAt());

  }

  @Override
  public CertificateCredentialValue findTransitionalVersion(final String caName) {
    final List<CredentialVersion> credentialVersions = certificateVersionDataService.findBothActiveCertAndTransitionalCert(caName);

    if (credentialVersions == null) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }

    final CertificateCredentialVersion transitionalVersion = (CertificateCredentialVersion) credentialVersions.stream().filter(version -> {
      if (!(version instanceof CertificateCredentialVersion)) {
        throw new ParameterizedValidationException(ErrorMessages.NOT_A_CA_NAME);
      }
      return ((CertificateCredentialVersion) version).isVersionTransitional();
    }).findFirst().orElse(null);

    if (transitionalVersion == null) {
      return null;
    } else if (!transitionalVersion.getParsedCertificate().isCa()) {
      throw new ParameterizedValidationException(ErrorMessages.CERT_NOT_CA);
    }

    return new CertificateCredentialValue(
            transitionalVersion.getCertificate(),
            transitionalVersion.getPrivateKey(),
            transitionalVersion.isCertificateAuthority(),
            transitionalVersion.isSelfSigned(),
            transitionalVersion.getGenerated(),
            transitionalVersion.isVersionTransitional(),
            transitionalVersion.getVersionCreatedAt());
  }
}
