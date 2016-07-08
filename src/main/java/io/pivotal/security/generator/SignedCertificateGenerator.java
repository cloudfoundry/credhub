package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Component
public class SignedCertificateGenerator {

  @Autowired
  DateTimeProvider timeProvider;

  @Autowired
  RandomSerialNumberGenerator serialNumberGenerator;

  public X509Certificate get(X500Principal issuerDn, PrivateKey issuerKey, KeyPair keyPair, CertificateSecretParameters params) throws Exception {
    Instant now = timeProvider.getNow().toInstant();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);

    X509CertificateHolder holder = new X509v3CertificateBuilder(
        asX500Name(issuerDn),
        serialNumberGenerator.generate(),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDurationDays()))),
        params.getDN(),
        publicKeyInfo
    ).build(contentSigner);

    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
  }

  private X500Name asX500Name(X500Principal x500Principal) {
    String name = x500Principal.getName();
    List<String> rdns = splitOnCommaCheckingForEscapedCommas(name);
    Collections.reverse(rdns);
    return new X500Name(String.join(",", rdns));
  }

  private List<String> splitOnCommaCheckingForEscapedCommas(String name) {
    List<String> result = new ArrayList<>();

    int i = 0;
    StringBuilder sb = new StringBuilder();
    while (i < name.length()) {
      char c = name.charAt(i);
      int peek = i + 1;
      if (c == '\\' && peek < name.length() && name.charAt(peek) == ',') {
        sb.append(c);
        sb.append(",");
        i++;
      } else if (c == ',') {
        if (sb.length() > 0) {
          result.add(sb.toString());
        }
        sb.setLength(0);
      } else {
        sb.append(c);
      }

      i++;
    }

    if (sb.length() > 0) {
      result.add(sb.toString());
    }

    return result;
  }
}
