package io.pivotal.security.generator;

import io.pivotal.security.model.CertificateSecretParameters;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import javax.validation.ValidationException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class RootCertificateProvider {
  private static final Pattern IP_ADDRESS_PATTERN = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\\d+)?$");
  private static final Pattern BAD_IP_ADDRESS_PATTERN = Pattern.compile("^(\\d+\\.){3}\\d+$");
  private static final Pattern DNS_PATTERN_INCLUDING_LEADING_WILDCARD = Pattern.compile("^(\\*\\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$");

  public X509Certificate get(KeyPair caKeyPair, CertificateSecretParameters params) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
    final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
    certGen.setPublicKey(caKeyPair.getPublic());
    certGen.setSignatureAlgorithm("SHA256withRSA");
    certGen.setSerialNumber(BigInteger.valueOf(1));

    final X500Principal dnName = new X500Principal(params.getDNString());
    certGen.setIssuerDN(dnName);
    certGen.setSubjectDN(dnName);

    Instant instant = Instant.now();
    final Date now = Date.from(instant);
    final Date later = Date.from(instant.plus(365, ChronoUnit.DAYS));
    certGen.setNotBefore(now);
    certGen.setNotAfter(later);

    addAlternativeNames(params, certGen);

    X509Certificate caCert = certGen.generate(caKeyPair.getPrivate(), "BC");

    caCert.verify(caKeyPair.getPublic());

    return caCert;
  }

  private void addAlternativeNames(CertificateSecretParameters params, X509V3CertificateGenerator certGen) {
    List<String> alternateNames = params.getAlternativeNames();
    GeneralName[] genNames = new GeneralName[alternateNames.size()];
    for (int i = 0; i < alternateNames.size(); i++) {
      String name = alternateNames.get(i);
      if (IP_ADDRESS_PATTERN.matcher(name).matches()) {
        genNames[i] = new GeneralName(GeneralName.iPAddress, name);
      } else if (BAD_IP_ADDRESS_PATTERN.matcher(name).matches()) {
        throw new ValidationException("error.invalid_alternate_name");
      } else if (DNS_PATTERN_INCLUDING_LEADING_WILDCARD.matcher(name).matches()) {
        genNames[i] = new GeneralName(GeneralName.dNSName, name);
      } else {
        throw new ValidationException("error.invalid_alternate_name");
      }
    }
    certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(genNames));
  }
}
