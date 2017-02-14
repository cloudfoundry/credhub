package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedRsaSshSecretData;
import io.pivotal.security.service.Encryption;


public abstract class NamedRsaSshSecret extends NamedSecret<NamedRsaSshSecret> {

  private NamedRsaSshSecretData delegate;

  public NamedRsaSshSecret(NamedRsaSshSecretData delegate){
    super(delegate);
    this.delegate = delegate;
  }


  public String getPublicKey() {
    return delegate.getPublicKey();
  }

  public <T extends NamedRsaSshSecret> T setPublicKey(String publicKey) {
    this.delegate.setPublicKey(publicKey);
    return (T) this;
  }

  public String getPrivateKey() {
    return encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()
    );
  }

  public <T extends NamedRsaSshSecret> T setPrivateKey(String privateKey) {
    final Encryption encryption = encryptor.encrypt(privateKey);

    delegate.setEncryptedValue(encryption.encryptedValue);
    delegate.setNonce(encryption.nonce);
    delegate.setEncryptionKeyUuid(encryptor.getActiveUuid());

    return (T) this;
  }


}
