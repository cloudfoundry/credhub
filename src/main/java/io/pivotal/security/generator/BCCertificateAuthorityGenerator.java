package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.secret.CertificateAuthority;
import io.pivotal.security.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

@Component
public class BCCertificateAuthorityGenerator implements SecretGenerator<CertificateSecretParameters, CertificateAuthority> {

  @Autowired
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  SignedCertificateGenerator signedCertificateGenerator;

  @Override
  public CertificateAuthority generateSecret(CertificateSecretParameters params) {
    try {
      KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      X509Certificate ca = signedCertificateGenerator.getSelfSigned(keyPair, params);
      String certPem = CertificateFormatter.pemOf(ca);
      String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
      return new CertificateAuthority("root", certPem, privatePem);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
