package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.PrivateKeyReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.cloudfoundry.credhub.util.CertificateFormatter.pemOf;

@Component
public class CertificateGenerator implements CredentialGenerator<CertificateCredentialValue> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;


  @Autowired
  public CertificateGenerator(
      LibcryptoRsaKeyPairGenerator keyGenerator,
      SignedCertificateGenerator signedCertificateGenerator,
      CertificateAuthorityService certificateAuthorityService) {
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
  }

  @Override
  public CertificateCredentialValue generateCredential(GenerationParameters p) {
    CertificateGenerationParameters params = (CertificateGenerationParameters) p;
    KeyPair keyPair;
    String privatePem;
    try {
      keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      privatePem = pemOf(keyPair.getPrivate());
    } catch (Exception e) {
        throw new RuntimeException(e);
    }

    if (params.isSelfSigned()) {
      try {
        String cert = pemOf(signedCertificateGenerator.getSelfSigned(keyPair, params));
        return new CertificateCredentialValue(cert, cert, privatePem, null);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    } else {
      String caName = params.getCaName();
        CertificateCredentialValue ca = certificateAuthorityService.findActiveVersion(caName);
        if (ca.getPrivateKey() == null) {
          throw new ParameterizedValidationException("error.ca_missing_private_key");
        }
      String caCertificate = ca.getCertificate();

        try {
          X509Certificate cert = signedCertificateGenerator.getSignedByIssuer(
              keyPair,
              params,
              CertificateReader.getCertificate(caCertificate),
              PrivateKeyReader.getPrivateKey(ca.getPrivateKey())
          );
          return new CertificateCredentialValue(caCertificate, pemOf(cert), privatePem, caName);
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
    }
  }
}
