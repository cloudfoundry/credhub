package io.pivotal.security.domain;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.SshPublicKeyParser;
import io.pivotal.security.view.SecretKind;
import java.util.ArrayList;
import java.util.List;

public class NamedSshSecret extends NamedSecret<NamedSshSecret> {

  private NamedSshSecretData delegate;

  public NamedSshSecret(NamedSshSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedSshSecret(String name) {
    this(new NamedSshSecretData(name));
  }

  public NamedSshSecret() {
    this(new NamedSshSecretData());
  }

  public static NamedSecret createNewVersion(NamedSshSecret existing, String name,
      KeySetRequestFields fields, Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries) {
    NamedSshSecret secret;

    if (existing == null) {
      secret = new NamedSshSecret(name);
    } else {
      secret = new NamedSshSecret();
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

  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public NamedSshSecret setPublicKey(String publicKey) {
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

  public NamedSshSecret setPrivateKey(String privateKey) {
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

  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  public int getKeyLength() {
    return new SshPublicKeyParser(getPublicKey()).getKeyLength();
  }

  public String getComment() {
    return new SshPublicKeyParser(getPublicKey()).getComment();
  }

  public String getFingerprint() {
    return new SshPublicKeyParser(getPublicKey()).getFingerprint();
  }
}
