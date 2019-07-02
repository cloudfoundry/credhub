package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.services.CertificateAuthorityService;
import org.cloudfoundry.credhub.utils.CertificateFormatter;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.cloudfoundry.credhub.utils.PrivateKeyReader;

@Component
public class CertificateGenerator implements CredentialGenerator<CertificateCredentialValue> {

  private final RsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;


  @Autowired
  public CertificateGenerator(
    final RsaKeyPairGenerator keyGenerator,
    final SignedCertificateGenerator signedCertificateGenerator,
    final CertificateAuthorityService certificateAuthorityService) {
    super();
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
  }

  @Override
  public CertificateCredentialValue generateCredential(final GenerationParameters p) {
    final CertificateGenerationParameters params = (CertificateGenerationParameters) p;
    final KeyPair keyPair;
    final String privatePem;
    try {
      keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }

    if (params.isSelfSigned()) {
      try {
        final String cert = CertificateFormatter.pemOf(signedCertificateGenerator.getSelfSigned(keyPair, params));
        return new CertificateCredentialValue(cert, cert, privatePem, null, params.isCa(), params.isSelfSigned(), true, false);
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    } else {
      final String caName = params.getCaName();
      final CertificateCredentialValue ca = certificateAuthorityService.findActiveVersion(caName);
      if (ca.getPrivateKey() == null) {
        throw new ParameterizedValidationException(ErrorMessages.CA_MISSING_PRIVATE_KEY);
      }
      final String caCertificate = ca.getCertificate();

      try {

        final CertificateReader certificateReader = new CertificateReader(caCertificate);

        final X509Certificate cert = signedCertificateGenerator.getSignedByIssuer(
          keyPair,
          params,
          certificateReader.getCertificate(),
          PrivateKeyReader.getPrivateKey(ca.getPrivateKey())
        );
        return new CertificateCredentialValue(caCertificate, CertificateFormatter.pemOf(cert), privatePem, caName, params.isCa(), params.isSelfSigned(), true, false);
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }
  }
}
