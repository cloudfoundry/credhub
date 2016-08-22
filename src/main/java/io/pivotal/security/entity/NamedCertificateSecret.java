package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.EncryptionServiceImpl;
import io.pivotal.security.view.CertificateSecret;

import javax.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "CertificateSecret")
@DiscriminatorValue("cert")
public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> {

  @Column(length = 7000)
  private String root;

  @Column(length = 7000)
  private String certificate;

  @Transient
  private String privateKey;

  public static NamedCertificateSecret make(String name, String root, String certificate, String privateKey) {
    return new NamedCertificateSecret(name)
        .setRoot(root)
        .setCertificate(certificate)
        .setPrivateKey(privateKey);
  }

  public NamedCertificateSecret() {
  }

  public NamedCertificateSecret(String name) {
    super(name);
  }

  public String getRoot() {
    return root;
  }

  public NamedCertificateSecret setRoot(String root) {
    this.root = root;
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
    byte[] encryptedValue = getEncryptedValue();
    if (encryptedValue == null) {
      return null;
    }
    try {
      EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
      return encryptionService.decrypt(getNonce(), encryptedValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    if (Objects.equals(privateKey, this.privateKey)) {
      return this;
    }
    if (privateKey == null) {
      this.privateKey = null;
      setEncryptedValue(null);
      setNonce(null);
    } else {
      try {
        EncryptionService encryptionService = EncryptionServiceProvider.getInstance();
        EncryptionServiceImpl.Encryption encryption = encryptionService.encrypt(privateKey);
        this.privateKey = privateKey;
        setNonce(encryption.nonce);
        setEncryptedValue(encryption.encryptedValue);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
    return this;
  }

  @Override
  public CertificateSecret generateView() {
    return new CertificateSecret(root, certificate, getPrivateKey()).setUpdatedAt(getUpdatedAt());
  }
}