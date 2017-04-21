package io.pivotal.security.domain;

import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;

import java.util.ArrayList;
import java.util.List;

public class RsaCredential extends Credential<RsaCredential> {

  private RsaCredentialData delegate;

  public RsaCredential(RsaCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public RsaCredential(String name) {
    this(new RsaCredentialData(name));
  }

  public RsaCredential() {
    this(new RsaCredentialData());
  }

  public static RsaCredential createNewVersion(RsaCredential existing, String name,
                                               KeySetRequestFields fields, Encryptor encryptor,
                                               List<AccessControlEntry> accessControlEntries) {
    RsaCredential credential;

    if (existing == null) {
      credential = new RsaCredential(name);
    } else {
      credential = new RsaCredential();
      credential.copyNameReferenceFrom(existing);
    }

    if (accessControlEntries == null) {
      accessControlEntries = new ArrayList<>();
    }

    credential.setAccessControlList(accessControlEntries);

    credential.setEncryptor(encryptor);
    credential.setPrivateKey(fields.getPrivateKey());
    credential.setPublicKey(fields.getPublicKey());

    return credential;
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
  public String getCredentialType() {
    return delegate.getCredentialType();
  }
}
