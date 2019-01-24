package org.cloudfoundry.credhub.generator;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.PrivateKeyReader;

import static org.cloudfoundry.credhub.util.CertificateFormatter.pemOf;

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
      privatePem = pemOf(keyPair.getPrivate());
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }

    if (params.isSelfSigned()) {
      try {
        final String cert = pemOf(signedCertificateGenerator.getSelfSigned(keyPair, params));
        return new CertificateCredentialValue(cert, cert, privatePem, null);
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    } else {
      final String caName = params.getCaName();
      final CertificateCredentialValue ca = certificateAuthorityService.findActiveVersion(caName);
      if (ca.getPrivateKey() == null) {
        throw new ParameterizedValidationException("error.ca_missing_private_key");
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
        return new CertificateCredentialValue(caCertificate, pemOf(cert), privatePem, caName);
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }
  }
}
