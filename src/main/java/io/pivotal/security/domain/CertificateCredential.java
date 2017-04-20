package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.CertificateSetRequestFields;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class CertificateCredential extends Credential<CertificateCredential> {

  private NamedCertificateSecretData delegate;

  public CertificateCredential(NamedCertificateSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public CertificateCredential(String name) {
    this(new NamedCertificateSecretData(name));
  }

  public CertificateCredential() {
    this(new NamedCertificateSecretData());
  }

  public static CertificateCredential createNewVersion(
      CertificateCredential existing,
      String name,
      CertificateSetRequestFields fields,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    CertificateCredential secret;

    if (existing == null) {
      secret = new CertificateCredential(name);
    } else {
      secret = new CertificateCredential();
      secret.copyNameReferenceFrom(existing);
      secret.setCaName(existing.getCaName());
    }

    secret.setAccessControlList(accessControlEntries);

    secret.setEncryptor(encryptor);
    secret.setPrivateKey(fields.getPrivateKey());
    secret.setCertificate(fields.getCertificate());
    secret.setCa(fields.getCa());
    secret.setCaName(fields.getCaName());
    return secret;
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
    return encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()
    );
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
  public String getSecretType() {
    return delegate.getSecretType();
  }

  public void rotate() {
    String decryptedPrivateKey = this.getPrivateKey();
    this.setPrivateKey(decryptedPrivateKey);
  }
}
