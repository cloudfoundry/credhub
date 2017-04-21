package io.pivotal.security.domain;

import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.CertificateSetRequestFields;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class CertificateCredential extends Credential<CertificateCredential> {

  private CertificateCredentialData delegate;

  public CertificateCredential(CertificateCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public CertificateCredential(String name) {
    this(new CertificateCredentialData(name));
  }

  public CertificateCredential() {
    this(new CertificateCredentialData());
  }

  public static CertificateCredential createNewVersion(
      CertificateCredential existing,
      String name,
      CertificateSetRequestFields fields,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    CertificateCredential credential;

    if (existing == null) {
      credential = new CertificateCredential(name);
    } else {
      credential = new CertificateCredential();
      credential.copyNameReferenceFrom(existing);
      credential.setCaName(existing.getCaName());
    }

    credential.setAccessControlList(accessControlEntries);

    credential.setEncryptor(encryptor);
    credential.setPrivateKey(fields.getPrivateKey());
    credential.setCertificate(fields.getCertificate());
    credential.setCa(fields.getCa());
    credential.setCaName(fields.getCaName());
    return credential;
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
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public void rotate() {
    String decryptedPrivateKey = this.getPrivateKey();
    this.setPrivateKey(decryptedPrivateKey);
  }
}
