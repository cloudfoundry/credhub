package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
public class SignedCertificateGenerator {

  final FactoryBean<Instant> timeProvider;

  @Autowired
  public SignedCertificateGenerator(FactoryBean<Instant> timeProvider) {
    this.timeProvider = timeProvider;
  }

  public X509Certificate get(X500Principal issuerDn, PrivateKey issuerKey, KeyPair keyPair, CertificateSecretParameters params) throws Exception {
    Instant now = timeProvider.getObject();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(issuerKey);

    X509CertificateHolder holder = new X509v3CertificateBuilder(
        new X500Name(issuerDn.getName()),
        BigInteger.valueOf(1),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDurationDays()))),
        new X500Name(params.getDNString()),
        publicKeyInfo
    ).build(contentSigner);

    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
  }
}
