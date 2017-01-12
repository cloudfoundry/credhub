package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateSecret;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
public class SignedCertificateGenerator {
  @Autowired
  DateTimeProvider timeProvider;

  @Autowired
  RandomSerialNumberGenerator serialNumberGenerator;

  @Autowired
  BouncyCastleProvider provider;

  X509Certificate getSignedByIssuer(X500Name issuerDn, PrivateKey issuerKey, KeyPair keyPair,
                                    CertificateSecretParameters params) throws Exception {
    return get(issuerDn, issuerKey, keyPair, params);
  }

  X509Certificate getSelfSigned(KeyPair keyPair, CertificateSecretParameters params) throws Exception {
    return get(params.getDN(), keyPair.getPrivate(), keyPair, params);
  }

  private X509Certificate get(X500Name issuerDn, PrivateKey issuerKey, KeyPair keyPair, CertificateSecretParameters
      params) throws Exception {
    Instant now = timeProvider.getNow().toInstant();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build(issuerKey);

    final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
        issuerDn,
        serialNumberGenerator.generate(),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDurationDays()))),
        params.getDN(),
        publicKeyInfo
    );

    if (params.getAlternativeNames() != null) {
      certificateBuilder.addExtension(Extension.subjectAlternativeName, false, params.getAlternativeNames());
    }

    if (params.getKeyUsage() != null) {
      certificateBuilder.addExtension(Extension.keyUsage, true, params.getKeyUsage());
    }

    if (params.getExtendedKeyUsage() != null) {
      certificateBuilder.addExtension(Extension.extendedKeyUsage, false, params.getExtendedKeyUsage());
    }

    certificateBuilder.addExtension(Extension.basicConstraints, true,
        new BasicConstraints(!NamedCertificateSecret.SECRET_TYPE.equals(params.getType())));

    X509CertificateHolder holder = certificateBuilder.build(contentSigner);

    return new JcaX509CertificateConverter().setProvider(provider).getCertificate(holder);
  }
}
