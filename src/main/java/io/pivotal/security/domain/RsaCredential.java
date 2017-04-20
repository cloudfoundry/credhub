package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;

import java.util.ArrayList;
import java.util.List;

public class RsaCredential extends Credential<RsaCredential> {

  private NamedRsaSecretData delegate;

  public RsaCredential(NamedRsaSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public RsaCredential(String name) {
    this(new NamedRsaSecretData(name));
  }

  public RsaCredential() {
    this(new NamedRsaSecretData());
  }

  public static RsaCredential createNewVersion(RsaCredential existing, String name,
                                               KeySetRequestFields fields, Encryptor encryptor,
                                               List<AccessControlEntry> accessControlEntries) {
    RsaCredential secret;

    if (existing == null) {
      secret = new RsaCredential(name);
    } else {
      secret = new RsaCredential();
      secret.copyNameReferenceFrom(existing);
    }

    if (accessControlEntries == null) {
      accessControlEntries = new ArrayList<>();
    }

    secret.setAccessControlList(accessControlEntries);

    secret.setEncryptor(encryptor);
    secret.setPrivateKey(fields.getPrivateKey());
    secret.setPublicKey(fields.getPublicKey());

    return secret;
  }

  public int getKeyLength() {
    return delegate.getKeyLength();
  }

  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public RsaCredential setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return this;
  }

  public String getPrivateKey() {
    return encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()
    );
  }

  public RsaCredential setPrivateKey(String privateKey) {
    final Encryption encryption = encryptor.encrypt(privateKey);

    delegate.setEncryptedValue(encryption.encryptedValue);
    delegate.setNonce(encryption.nonce);
    delegate.setEncryptionKeyUuid(encryption.canaryUuid);

    return this;
  }

  public void rotate() {
    String decryptedValue = this.getPrivateKey();
    this.setPrivateKey(decryptedValue);
  }


  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }
}
