package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.view.SecretKind;
import org.apache.commons.codec.digest.DigestUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class NamedSshSecret extends NamedRsaSshSecret {

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

  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  public int getKeyLength() {
    return delegate.getKeyLength();
  }

  public String getComment() {
    return delegate.getComment();
  }

  public String getPublicKeyFingerprint() throws NoSuchAlgorithmException {
    if (delegate.getPublicKey() != null) {
      String publicKeyWithoutPrefix = delegate.getPublicKey().replace("ssh-rsa ", "");
      byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyWithoutPrefix);

      final MessageDigest sha256Digest = DigestUtils.getSha256Digest();
      final byte[] fingerprint = sha256Digest.digest(decodedPublicKey);

      return Base64.getEncoder().withoutPadding().encodeToString(fingerprint);
    }
    return null;
  }
}
