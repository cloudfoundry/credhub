package io.pivotal.security.util;

import static java.lang.Math.toIntExact;
import static java.time.temporal.ChronoUnit.DAYS;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class CertificateReader {
  private final X509Certificate certificate;
  private final X509CertificateHolder certificateHolder;
  private X500Name subjectName;

  public CertificateReader(String pemString) {
    try {
      certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
          .generateCertificate(new ByteArrayInputStream(pemString.getBytes()));
      certificateHolder = (X509CertificateHolder) (new PEMParser((new StringReader(pemString))).readObject());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public boolean isValid() {
    return certificate != null;
  }

  public GeneralNames getAlternativeNames() {
    Extension encodedAlternativeNames = certificateHolder.getExtension(Extension.subjectAlternativeName);
    return encodedAlternativeNames != null ? GeneralNames.getInstance(encodedAlternativeNames.getParsedValue()) : null;
  }

  public int getDurationDays() {
    return toIntExact(DAYS.between(
        certificate.getNotBefore().toInstant(),
        certificate.getNotAfter().toInstant()
    ));
  }

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return ExtendedKeyUsage.fromExtensions(certificateHolder.getExtensions());
  }

  public X500Name getSubjectName() {
    subjectName = new X500Name(certificate.getSubjectDN().getName());
    return subjectName;
  }

  public int getKeyLength() {
    return ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength();
  }

  public KeyUsage getKeyUsage() {
    return KeyUsage.fromExtensions(certificateHolder.getExtensions());
  }

  public Boolean isSelfSigned() {
    final String issuerName = certificate.getIssuerDN().getName();

    if (!issuerName.equals(getSubjectName().toString())) {
      return false;
    } else {
      try {
        certificate.verify(certificate.getPublicKey());
        return true;
      } catch(SignatureException | InvalidKeyException e) {
        return false;
      } catch(Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  public boolean isCA() {
    Extensions extensions = certificateHolder.getExtensions();
    BasicConstraints basicConstraints = null;

    if (extensions != null) {
      basicConstraints = BasicConstraints
          .fromExtensions(Extensions.getInstance(extensions));
    }

    return basicConstraints != null && basicConstraints.isCA();
  }
}
