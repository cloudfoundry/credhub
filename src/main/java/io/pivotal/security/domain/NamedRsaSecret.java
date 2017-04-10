package io.pivotal.security.domain;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;
import java.util.ArrayList;
import java.util.List;

public class NamedRsaSecret extends NamedSecret<NamedRsaSecret> {

  private NamedRsaSecretData delegate;

  public NamedRsaSecret(NamedRsaSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedRsaSecret(String name) {
    this(new NamedRsaSecretData(name));
  }

  public NamedRsaSecret() {
    this(new NamedRsaSecretData());
  }

  public static NamedSecret createNewVersion(NamedRsaSecret existing, String name,
      KeySetRequestFields fields, Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries) {
    NamedRsaSecret secret;

    if (existing == null) {
      secret = new NamedRsaSecret(name);
    } else {
      secret = new NamedRsaSecret();
      secret.copyNameReferenceFrom(existing);
    }

    if (accessControlEntries == null) {
      accessControlEntries = new ArrayList<>();
    }

    List<AccessEntryData> accessEntryData = secret.getAccessEntryData(accessControlEntries);

    secret.setAccessControlList(accessEntryData);

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

  public NamedRsaSecret setPublicKey(String publicKey) {
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

  public NamedRsaSecret setPrivateKey(String privateKey) {
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
