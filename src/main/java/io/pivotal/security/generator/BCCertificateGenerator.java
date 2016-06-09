package io.pivotal.security.generator;

import io.pivotal.security.model.CertificateSecret;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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
  public CertificateSecret generateCertificate() throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    KeyPair keyPair = keyGenerator.generateKeyPair();
    X509Certificate caCert = rootCertificateProvider.get();

    return new CertificateSecret(new X509CertificateHolder(caCert), keyPair.getPublic().getEncoded().toString(), keyPair.getPrivate().getEncoded().toString());
  }


}
