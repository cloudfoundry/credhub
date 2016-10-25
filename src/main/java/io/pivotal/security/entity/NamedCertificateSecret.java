package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.util.StringUtils;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static java.time.temporal.ChronoUnit.DAYS;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret {
  private static final String RSA_START = "-----BEGIN CERTIFICATE-----";
  private static final String RSA_END = "-----END CERTIFICATE-----";
  public static final String NEW_LINE = "\n";

  @Column(length = 7000)
  private String ca;

  @Column(length = 7000)
  private String certificate;

  @Column
  private String caName;

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name) {
    super(name);
  }

  public NamedCertificateSecret(String name, String ca, String certificate, String privateKey) {
    super(name);
    this.ca = ca;
    this.certificate = certificate;
    setPrivateKey(privateKey);
  }

  public String getCa() {
    return ca;
  }

  public NamedCertificateSecret setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateSecret setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getPrivateKey() {
    return SecretEncryptionHelperProvider.getInstance().retrieveClearTextValue(this);
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedValue(this, privateKey);
    return this;
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.CERTIFICATE;
  }

  @Override
  public String getSecretType() {
    throw new UnsupportedOperationException();
  }

  public NamedCertificateSecret setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  public int getKeyLength() {
    // We could conceivably use the CertificateHolder again, but it quickly became even messier
    // and was giving us a strange off-by-1 error (e.g., 4097 bits instead of 4096).
    // BouncyCastle's KeyFactorySpi.generatePublic also works (via certificateHolder.getSubjectPublicKeyInfo),
    // but was still slightly messier/less clear than the below.
    String certificateString = getCertificate();

    if (StringUtils.isEmpty(certificateString)) {
      return 0;
    }

    String strippedCertificate = certificateString
        .replaceFirst(RSA_START, "")
        .replaceFirst(RSA_END, "")
        .replaceAll(NEW_LINE, "");
    byte[] byteCertificate = Base64.decodeBase64(strippedCertificate.getBytes());

    try {
      ByteArrayInputStream byteStream = new ByteArrayInputStream(byteCertificate);
      Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(byteStream);
      return ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength();
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  public int getDurationDays() {
    X509CertificateHolder certificateHolder = getCertificateHolder();

    if (certificateHolder == null) {
      return 0;
    }

    Date startDate = certificateHolder.getNotBefore();
    Date endDate = certificateHolder.getNotAfter();

    return (int) DAYS.between(startDate.toInstant(), endDate.toInstant());
  }

  public Extension getAlternativeNames() {
    X509CertificateHolder certificateHolder = getCertificateHolder();

    if (certificateHolder == null) {
      return null;
    } else {
      return certificateHolder.getExtension(Extension.subjectAlternativeName);
    }
  }

  private X509CertificateHolder getCertificateHolder() {
    String certificate = getCertificate();

    if (StringUtils.isEmpty(certificate)) {
      return null;
    }

    try {
      return (X509CertificateHolder) (new PEMParser((new StringReader(certificate))).readObject());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
