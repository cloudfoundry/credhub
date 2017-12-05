package org.cloudfoundry.credhub.util;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import javax.security.auth.x500.X500Principal;

import static org.cloudfoundry.credhub.util.StringUtil.UTF_8;
import static java.lang.Math.toIntExact;
import static java.time.temporal.ChronoUnit.DAYS;

public class CertificateReader {

  private final X509Certificate certificate;
  private final X509CertificateHolder certificateHolder;
  private X500Principal subjectName;

  public CertificateReader(String pemString) {
    try {
      certificate = (X509Certificate) CertificateFactory
          .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
          .generateCertificate(new ByteArrayInputStream(pemString.getBytes(UTF_8)));
      certificateHolder = (X509CertificateHolder) (new PEMParser((new StringReader(pemString)))
          .readObject());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static X509Certificate getCertificate(String pemString)
      throws CertificateException, NoSuchProviderException {
    return (X509Certificate) CertificateFactory
        .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
        .generateCertificate(new ByteArrayInputStream(pemString.getBytes(UTF_8)));
  }

  public boolean isValid() {
    return certificate != null;
  }

  public GeneralNames getAlternativeNames() {
    Extension encodedAlternativeNames = certificateHolder
        .getExtension(Extension.subjectAlternativeName);
    return encodedAlternativeNames != null ? GeneralNames
        .getInstance(encodedAlternativeNames.getParsedValue()) : null;
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

  public X500Principal getSubjectName() {
    subjectName = new X500Principal(certificate.getSubjectDN().getName());
    return subjectName;
  }

  public boolean isSignedByCa(String caValue) {
    try {
      X509Certificate ca = getCertificate(caValue);
      if(ca != null) {
        certificate.verify(ca.getPublicKey());
        return true;
      }
      return false;
    } catch (SignatureException | InvalidKeyException e) {
      return false;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public int getKeyLength() {
    return ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength();
  }

  public KeyUsage getKeyUsage() {
    return KeyUsage.fromExtensions(certificateHolder.getExtensions());
  }

  public boolean isSelfSigned() {
    final String issuerName = certificate.getIssuerDN().getName();

    if (!issuerName.equals(certificate.getSubjectDN().toString())) {
      return false;
    } else {
      try {
        certificate.verify(certificate.getPublicKey());
        return true;
      } catch (SignatureException | InvalidKeyException e) {
        return false;
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  public boolean isCa() {
    Extensions extensions = certificateHolder.getExtensions();
    BasicConstraints basicConstraints = null;

    if (extensions != null) {
      basicConstraints = BasicConstraints
          .fromExtensions(Extensions.getInstance(extensions));
    }

    return basicConstraints != null && basicConstraints.isCA();
  }
}
