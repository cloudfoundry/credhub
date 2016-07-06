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
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

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
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);

    X509CertificateHolder holder = new X509v3CertificateBuilder(
        asX500Name(issuerDn),
        BigInteger.valueOf(1),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDurationDays()))),
        params.getDN(),
        publicKeyInfo
    ).build(contentSigner);

    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
  }

  private X500Name asX500Name(X500Principal x500Principal) {
    List<String> rdns = Arrays.asList(x500Principal.getName().split(","));
    Collections.reverse(rdns);
    return new X500Name(String.join(",", rdns));
  }
}
