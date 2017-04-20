package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.SshPublicKeyParser;

import java.util.ArrayList;
import java.util.List;

public class SshCredential extends Credential<SshCredential> {

  private NamedSshSecretData delegate;

  public SshCredential(NamedSshSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public SshCredential(String name) {
    this(new NamedSshSecretData(name));
  }

  public SshCredential() {
    this(new NamedSshSecretData());
  }

  public static SshCredential createNewVersion(SshCredential existing, String name,
                                               KeySetRequestFields fields, Encryptor encryptor,
                                               List<AccessControlEntry> accessControlEntries) {
    SshCredential secret;

    if (existing == null) {
      secret = new SshCredential(name);
    } else {
      secret = new SshCredential();
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

  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public SshCredential setPublicKey(String publicKey) {
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

  public SshCredential setPrivateKey(String privateKey) {
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
