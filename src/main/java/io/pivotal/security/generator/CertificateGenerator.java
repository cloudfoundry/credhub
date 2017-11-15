package io.pivotal.security.generator;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.domain.CertificateGenerationParameters;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.util.CertificateReader;
import io.pivotal.security.util.PrivateKeyReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static io.pivotal.security.util.CertificateFormatter.pemOf;

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

    X509Certificate cert;
    String caName = null;
    String caCertificate = null;

    if (params.isSelfSigned()) {
      try {
        cert = signedCertificateGenerator.getSelfSigned(keyPair, params);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    } else {
        caName = params.getCaName();
        CertificateCredentialValue ca = certificateAuthorityService.findMostRecent(caName);
        if (ca.getPrivateKey() == null) {
          throw new ParameterizedValidationException("error.ca_missing_private_key");
        }
        caCertificate = ca.getCertificate();

        try {
          cert = signedCertificateGenerator.getSignedByIssuer(
              keyPair,
              params,
              CertificateReader.getCertificate(caCertificate),
              PrivateKeyReader.getPrivateKey(ca.getPrivateKey())
          );
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
    }

    try {
      return new CertificateCredentialValue(caCertificate, pemOf(cert), privatePem, caName);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
