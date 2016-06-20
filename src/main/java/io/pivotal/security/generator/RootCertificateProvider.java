package io.pivotal.security.generator;

import io.pivotal.security.model.CertificateSecretParameters;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

@Component
public class RootCertificateProvider {
  public X509Certificate get(KeyPair caKeyPair, CertificateSecretParameters params) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
    final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

    final X500Principal dnName = new X500Principal(params.getDNString());

    Instant instant = Instant.now();
    final Date now = Date.from(instant);
    final Date later = Date.from(instant.plus(365, ChronoUnit.DAYS));

    certGen.setSerialNumber(BigInteger.valueOf(1));
    certGen.setIssuerDN(dnName);
    certGen.setNotBefore(now);
    certGen.setNotAfter(later);
    certGen.setSubjectDN(dnName);

    certGen.setPublicKey(caKeyPair.getPublic());
    certGen.setSignatureAlgorithm("SHA256withRSA");

    addAlternateNames(params, certGen);

    X509Certificate caCert = certGen.generate(caKeyPair.getPrivate(), "BC");

    caCert.verify(caKeyPair.getPublic());

    return caCert;
  }

  private void addAlternateNames(CertificateSecretParameters params, X509V3CertificateGenerator certGen) {
    List<String> alternateNames = params.getAlternateNames();
    GeneralName[] genNames = new GeneralName[alternateNames.size()];
    for (int i = 0; i < alternateNames.size(); i++) {
      genNames[i] = new GeneralName(GeneralName.rfc822Name, alternateNames.get(i));
    }
    certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(genNames));
  }
}
