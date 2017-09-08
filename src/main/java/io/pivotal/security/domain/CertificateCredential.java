package io.pivotal.security.domain;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.CertificateReader;
import org.apache.commons.lang3.StringUtils;

public class CertificateCredential extends Credential<CertificateCredential> {

  private CertificateCredentialData delegate;
  private CertificateReader parsedCertificate;

  public CertificateCredential(CertificateCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
    if (StringUtils.isNotEmpty(delegate.getCertificate())) {
      this.parsedCertificate = new CertificateReader(delegate.getCertificate());
    }
  }

  public CertificateCredential(String name) {
    this(new CertificateCredentialData(name));
  }

  public CertificateCredential() {
    this(new CertificateCredentialData());
  }

  public CertificateCredential(CertificateCredentialValue certificate, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setCa(certificate.getCa());
    this.setCertificate(certificate.getCertificate());
    this.setPrivateKey(certificate.getPrivateKey());
    this.setCaName(certificate.getCaName());
    if (StringUtils.isNotEmpty(delegate.getCertificate())) {
      this.parsedCertificate = new CertificateReader(certificate.getCertificate());
    }
  }

  public CertificateReader getParsedCertificate() {
    return this.parsedCertificate;
  }

  public String getCa() {
    return delegate.getCa();
  }

  public CertificateCredential setCa(String ca) {
    delegate.setCa(ca);
    return this;
  }

  public String getCertificate() {
    return delegate.getCertificate();
  }

  public CertificateCredential setCertificate(String certificate) {
    delegate.setCertificate(certificate);
    return this;
  }

  public String getPrivateKey() {
    return encryptor.decrypt(new Encryption(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()));
  }

  public CertificateCredential setPrivateKey(String privateKey) {
    final Encryption encryption = encryptor.encrypt(privateKey);

    delegate.setNonce(encryption.nonce);
    delegate.setEncryptedValue(encryption.encryptedValue);
    delegate.setEncryptionKeyUuid(encryption.canaryUuid);

    return this;
  }

  public String getCaName() {
    return delegate.getCaName();
  }

  public CertificateCredential setCaName(String caName) {
    delegate.setCaName(caName);
    return this;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public void rotate() {
    String decryptedPrivateKey = this.getPrivateKey();
    this.setPrivateKey(decryptedPrivateKey);
  }
}
