package org.cloudfoundry.credhub.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMParser;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.exceptions.MissingCertificateException;
import org.cloudfoundry.credhub.exceptions.UnreadableCertificateException;
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters;
import org.jetbrains.annotations.Nullable;

import static java.lang.Math.toIntExact;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.DAYS;

public class CertificateReader {
  private final X509Certificate certificate;
  private final X509CertificateHolder certificateHolder;

  public CertificateReader(final String pemString) {
    super();
    if (pemString == null) {
      throw new MissingCertificateException();
    }

    try {
      certificate = parseStringIntoCertificate(pemString);
      certificateHolder = (X509CertificateHolder) (new PEMParser(new StringReader(pemString))
        .readObject());
    } catch (final IOException e) {
      throw new UnreadableCertificateException();
    } catch (final CertificateException e) {
      throw new MalformedCertificateException();
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }

    if (certificate == null) {
      throw new MalformedCertificateException();
    }
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public GeneralNames getAlternativeNames() {
    final Extension encodedAlternativeNames = certificateHolder
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
    return new X500Principal(certificate.getSubjectX500Principal().getName());
  }

  public boolean isSignedByCa(final String caValue) {
    try {
      final X509Certificate ca = parseStringIntoCertificate(caValue);
      if (ca != null) {

        certificate.verify(ca.getPublicKey());
        return true;
      }
      return false;
    } catch (final SignatureException | InvalidKeyException | CertificateException e) {
      return false;
    } catch (final Exception e) {
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
    final String issuerName = certificate.getIssuerX500Principal().getName();

    if (!issuerName.equals(certificate.getSubjectX500Principal().getName())) {
      return false;
    } else {
      try {
        certificate.verify(certificate.getPublicKey());
        return true;
      } catch (final SignatureException | InvalidKeyException e) {
        return false;
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  public boolean isCa() {
    final Extensions extensions = certificateHolder.getExtensions();
    BasicConstraints basicConstraints = null;

    if (extensions != null) {
      basicConstraints = BasicConstraints
        .fromExtensions(Extensions.getInstance(extensions));
    }

    return basicConstraints != null && basicConstraints.isCA();
  }

  public Instant getNotAfter() {
    if (certificate == null || certificate.getNotAfter() == null) {
      return null;
    }

    return certificate.getNotAfter().toInstant();
  }

  private X509Certificate parseStringIntoCertificate(final String pemString) throws CertificateException, NoSuchProviderException {
    return (X509Certificate) CertificateFactory
      .getInstance("X.509", BouncyCastleFipsProvider.PROVIDER_NAME)
      .generateCertificate(new ByteArrayInputStream(pemString.getBytes(UTF_8)));
  }

  public @Nullable String getCommonName() {
    return getX500NameAttribute(BCStyle.CN);
  }

  public @Nullable String getOrganization() {
    return getX500NameAttribute(BCStyle.O);
  }

  public @Nullable String getOrganizationUnit() {
    return getX500NameAttribute(BCStyle.OU);
  }

  public @Nullable String getLocality() {
    return getX500NameAttribute(BCStyle.L);
  }

  public @Nullable String getState() {
    return getX500NameAttribute(BCStyle.ST);
  }

  public @Nullable String getCountry() {
    return getX500NameAttribute(BCStyle.C);
  }

  public  @Nullable String[] getExtendedKeyUsageStrings() {
    final ExtendedKeyUsage extendedKeyUsage = getExtendedKeyUsage();
    if (extendedKeyUsage == null) {
      return null;
    }

    final KeyPurposeId[] keyPurposeIds = extendedKeyUsage.getUsages();
    final List<String> extendedKeyUsageList = new ArrayList<>();

    for (final KeyPurposeId keyPurposeId : keyPurposeIds) {
      if (keyPurposeId.equals(KeyPurposeId.id_kp_serverAuth)) {
        extendedKeyUsageList.add(CertificateGenerationRequestParameters.SERVER_AUTH);
      } else if (keyPurposeId.equals(KeyPurposeId.id_kp_clientAuth)) {
        extendedKeyUsageList.add(CertificateGenerationRequestParameters.CLIENT_AUTH);
      } else if (keyPurposeId.equals(KeyPurposeId.id_kp_codeSigning)) {
        extendedKeyUsageList.add(CertificateGenerationRequestParameters.CODE_SIGNING);
      } else if (keyPurposeId.equals(KeyPurposeId.id_kp_emailProtection)) {
        extendedKeyUsageList.add(CertificateGenerationRequestParameters.EMAIL_PROTECTION);
      } else if (keyPurposeId.equals(KeyPurposeId.id_kp_timeStamping)) {
        extendedKeyUsageList.add(CertificateGenerationRequestParameters.TIMESTAMPING);
      }
    }

    return extendedKeyUsageList.toArray(new String[0]);
  }

  public @Nullable String[] getKeyUsageStrings() {
    final KeyUsage keyUsage = getKeyUsage();
    if (keyUsage == null) {
      return null;
    }

    final List<String> keyUsageList = new ArrayList<>();

    if (keyUsage.hasUsages(KeyUsage.digitalSignature)) {
      keyUsageList.add(CertificateGenerationRequestParameters.DIGITAL_SIGNATURE);
    }
    if (keyUsage.hasUsages(KeyUsage.nonRepudiation)) {
      keyUsageList.add(CertificateGenerationRequestParameters.NON_REPUDIATION);
    }
    if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
      keyUsageList.add(CertificateGenerationRequestParameters.KEY_ENCIPHERMENT);
    }
    if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
      keyUsageList.add(CertificateGenerationRequestParameters.DATA_ENCIPHERMENT);
    }
    if (keyUsage.hasUsages(KeyUsage.keyAgreement)) {
      keyUsageList.add(CertificateGenerationRequestParameters.KEY_AGREEMENT);
    }
    if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
      keyUsageList.add(CertificateGenerationRequestParameters.KEY_CERT_SIGN);
    }
    if (keyUsage.hasUsages(KeyUsage.cRLSign)) {
      keyUsageList.add(CertificateGenerationRequestParameters.CRL_SIGN);
    }
    if (keyUsage.hasUsages(KeyUsage.encipherOnly)) {
      keyUsageList.add(CertificateGenerationRequestParameters.ENCIPHER_ONLY);
    }
    if (keyUsage.hasUsages(KeyUsage.decipherOnly)) {
      keyUsageList.add(CertificateGenerationRequestParameters.DECIPHER_ONLY);
    }

    return keyUsageList.toArray(new String[0]);
  }

  private @Nullable String getX500NameAttribute(final org.bouncycastle.asn1.ASN1ObjectIdentifier attribute) {
    final X500Name x500Name = new X500Name(certificate.getSubjectX500Principal().getName());
    final RDN[] rdns = x500Name.getRDNs(attribute);

    if (rdns.length == 0) {
      return null;
    }

    return rdns[0].getFirst().getValue().toString();
  }
}
