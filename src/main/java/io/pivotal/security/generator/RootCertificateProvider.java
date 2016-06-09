package io.pivotal.security.generator;

import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Component
public class RootCertificateProvider {
  public X509Certificate get() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
    final X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
    final X500Principal dnName = new X500Principal("O=Organization,ST=CA,C=US");

    Instant instant = Instant.now();
    final Date now = Date.from(instant);
    final Date later = Date.from(instant.plus(365, ChronoUnit.DAYS));

    certGen.setSerialNumber(BigInteger.valueOf(1));
    certGen.setIssuerDN(dnName);
    certGen.setNotBefore(now);
    certGen.setNotAfter(later);
    certGen.setSubjectDN(dnName);

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(2048);
    KeyPair caKeyPair = generator.generateKeyPair();
    certGen.setPublicKey(caKeyPair.getPublic());
    certGen.setSignatureAlgorithm("SHA256withRSA");
    X509Certificate caCert = certGen.generate(caKeyPair.getPrivate(), "BC");

    caCert.verify(caKeyPair.getPublic());

    return caCert;
  }
}
