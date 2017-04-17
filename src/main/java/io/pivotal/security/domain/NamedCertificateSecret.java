package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.CertificateSetRequestFields;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> {

  private NamedCertificateSecretData delegate;

  public NamedCertificateSecret(NamedCertificateSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedCertificateSecret(String name) {
    this(new NamedCertificateSecretData(name));
  }

  public NamedCertificateSecret() {
    this(new NamedCertificateSecretData());
  }

  public static NamedCertificateSecret createNewVersion(
      NamedCertificateSecret existing,
      String name,
      CertificateSetRequestFields fields,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    NamedCertificateSecret secret;

    if (existing == null) {
      secret = new NamedCertificateSecret(name);
    } else {
      secret = new NamedCertificateSecret();
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

  public NamedCertificateSecret setCa(String ca) {
    delegate.setCa(ca);
    return this;
  }

  public String getCertificate() {
    return delegate.getCertificate();
  }

  public NamedCertificateSecret setCertificate(String certificate) {
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

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    final Encryption encryption = encryptor.encrypt(privateKey);

    delegate.setNonce(encryption.nonce);
    delegate.setEncryptedValue(encryption.encryptedValue);
    delegate.setEncryptionKeyUuid(encryption.canaryUuid);

    return this;
  }

  public String getCaName() {
    return delegate.getCaName();
  }

  public NamedCertificateSecret setCaName(String caName) {
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
