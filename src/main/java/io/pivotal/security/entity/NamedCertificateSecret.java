package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.Certificate;
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret {

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

  public NamedCertificateSecret setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  public int getKeyLength() {
    String certificate = getCertificate();

    if (StringUtils.isEmpty(certificate)) {
      return 0;
    }

    String strippedCertificate = certificate
        .replaceFirst("-----BEGIN CERTIFICATE-----", "")
        .replaceFirst("-----END CERTIFICATE-----", "")
        .replaceAll("\n", "");
    byte[] byteCertificate = Base64.decodeBase64(strippedCertificate.getBytes());
    try {
      return ((RSAPublicKey) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(byteCertificate)).getPublicKey()).getModulus().bitLength();
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  public int getDurationDays() {
    String certificate = getCertificate();

    if (StringUtils.isEmpty(certificate)) {
      return 0;
    }

    String strippedCertificate = certificate
        .replaceFirst("-----BEGIN CERTIFICATE-----", "")
        .replaceFirst("-----END CERTIFICATE-----", "")
        .replaceAll("\n", "");
    byte[] byteCertificate = Base64.decodeBase64(strippedCertificate.getBytes());
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(byteCertificate);
    Certificate decodedCertificate = Certificate.getInstance(x509EncodedKeySpec.getEncoded());
    return (int) ((decodedCertificate.getEndDate().getDate().getTime() - decodedCertificate.getStartDate().getDate().getTime()) / 60 / 60 / 24 / 1000);
  }

  public Extension getAlternativeNames() {
    String certificate = getCertificate();

    if (StringUtils.isEmpty(certificate)) {
      return null;
    }

    try {
      X509CertificateHolder c = (X509CertificateHolder) (new PEMParser(new StringReader(certificate)).readObject());
      return c.getExtension(Extension.subjectAlternativeName);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
