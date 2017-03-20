package io.pivotal.security.domain;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.view.SecretKind;

import java.util.List;

import static io.pivotal.security.util.StringUtil.emptyToNull;

public class NamedRsaSecret extends NamedSecret<NamedRsaSecret> {

  private NamedRsaSecretData delegate;

  public NamedRsaSecret(NamedRsaSecretData delegate){
    super(delegate);
    this.delegate = delegate;
  }

  public NamedRsaSecret(String name) {
    this(new NamedRsaSecretData(name));
  }

  public NamedRsaSecret() {
    this(new NamedRsaSecretData());
  }

  public int getKeyLength(){
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
    delegate.setEncryptionKeyUuid(encryptor.getActiveUuid());

    return this;
  }

  public void rotate(){
    String decryptedValue = this.getPrivateKey();
    this.setPrivateKey(decryptedValue);
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  public static NamedSecret createNewVersion(NamedRsaSecret existing, String name, KeySetRequestFields fields, Encryptor encryptor, List<AccessControlEntry> accessControlEntries) {
    NamedRsaSecret secret;

    if (existing == null) {
      secret = new NamedRsaSecret(name);
    } else {
      secret = new NamedRsaSecret();
      secret.copyNameReferenceFrom(existing);
    }

    List<AccessEntryData> accessEntryData = getAccessEntryData(accessControlEntries, secret);

    secret.setAccessControlList(accessEntryData);

    secret.setEncryptor(encryptor);
    secret.setPrivateKey(emptyToNull(fields.getPrivateKey()));
    secret.setPublicKey(emptyToNull(fields.getPublicKey()));

    return secret;
  }
}
