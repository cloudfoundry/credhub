package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import io.pivotal.security.view.ParameterizedValidationException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class SignedCertificateGenerator {
  private static final Pattern IP_ADDRESS_PATTERN = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\\d+)?$");
  private static final Pattern BAD_IP_ADDRESS_PATTERN = Pattern.compile("^(\\d+\\.){3}\\d+$");
  private static final Pattern DNS_PATTERN_INCLUDING_LEADING_WILDCARD = Pattern.compile("^(\\*\\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$");

  @Autowired
  DateTimeProvider timeProvider;

  @Autowired
  RandomSerialNumberGenerator serialNumberGenerator;

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
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);

    final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
        issuerDn,
        serialNumberGenerator.generate(),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDurationDays()))),
        params.getDN(),
        publicKeyInfo
    );

    if (params.getAlternativeNames().size() > 0) {
      certificateBuilder.addExtension(Extension.subjectAlternativeName, false, getAlternativeNames(params));
    }

    certificateBuilder.addExtension(Extension.basicConstraints, true,
        new BasicConstraints(!"certificate".equals(params.getType())));

    X509CertificateHolder holder = certificateBuilder.build(contentSigner);

    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
  }

  private GeneralNames getAlternativeNames(CertificateSecretParameters params) {
    List<String> alternateNames = params.getAlternativeNames();
    GeneralName[] genNames = new GeneralName[alternateNames.size()];
    for (int i = 0; i < alternateNames.size(); i++) {
      String name = alternateNames.get(i);
      if (IP_ADDRESS_PATTERN.matcher(name).matches()) {
        genNames[i] = new GeneralName(GeneralName.iPAddress, name);
      } else if (BAD_IP_ADDRESS_PATTERN.matcher(name).matches()) {
        throw new ParameterizedValidationException("error.invalid_alternate_name");
      } else if (DNS_PATTERN_INCLUDING_LEADING_WILDCARD.matcher(name).matches()) {
        genNames[i] = new GeneralName(GeneralName.dNSName, name);
      } else {
        throw new ParameterizedValidationException("error.invalid_alternate_name");
      }
    }
    return new GeneralNames(genNames);
  }
}
