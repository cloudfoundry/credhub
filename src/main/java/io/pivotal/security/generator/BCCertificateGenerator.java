package io.pivotal.security.generator;

import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.CertificateSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Component
public class BCCertificateGenerator implements CertificateGenerator {

  @Autowired(required = true)
  KeyPairGenerator keyGenerator;

  @Autowired(required = true)
  RootCertificateProvider rootCertificateProvider;

  @Override
  public CertificateSecret generateCertificate(CertificateSecretParameters params) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, IOException {
    KeyPair keyPair = keyGenerator.generateKeyPair();
    X509Certificate cert = rootCertificateProvider.get(keyPair, params);
    String caPem = CertificateFormatter.pemOf(cert);
    String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
    return new CertificateSecret(caPem, privatePem);
  }
}
