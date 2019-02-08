package org.cloudfoundry.credhub.services;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.cloudfoundry.credhub.entities.EncryptedValue;

import static org.cloudfoundry.credhub.constants.EncryptionConstants.NONCE_SIZE;
import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CHARSET;

// This class is tested in BCEncryptionServiceTest.

public abstract class InternalEncryptionService implements EncryptionProvider {

  public abstract CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;

  public abstract AlgorithmParameterSpec generateParameterSpec(byte[] nonce);

  @Override
  public EncryptedValue encrypt(final EncryptionKey key, final String value) throws Exception {
    return encrypt(key.getUuid(), key.getKey(), value);
  }

  public EncryptedValue encrypt(final UUID canaryUuid, final Key key, final String value) throws Exception {
    final byte[] nonce = generateNonce();
    final AlgorithmParameterSpec parameterSpec = generateParameterSpec(nonce);
    final CipherWrapper encryptionCipher = getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

    final byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new EncryptedValue(canaryUuid, encrypted, nonce);
  }

  @Override
  public String decrypt(final EncryptionKey key, final byte[] encryptedValue, final byte[] nonce) throws Exception {
    return decrypt(key.getKey(), encryptedValue, nonce);
  }

  public String decrypt(final Key key, final byte[] encryptedValue, final byte[] nonce) throws Exception {
    final CipherWrapper decryptionCipher = getCipher();
    final AlgorithmParameterSpec parameterSpec = generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }

  private byte[] generateNonce() {
    final SecureRandom secureRandom = getSecureRandom();
    final byte[] nonce = new byte[NONCE_SIZE];
    secureRandom.nextBytes(nonce);
    return nonce;
  }

  public void reconnect(final Exception reasonForReconnect) throws Exception {
    throw reasonForReconnect;
  }

  public static class CipherWrapper {

    private final Cipher wrappedCipher;

    public CipherWrapper(final Cipher wrappedCipher) {
      super();
      this.wrappedCipher = wrappedCipher;
    }

    public void init(final int encryptMode, final Key key, final AlgorithmParameterSpec parameterSpec)
      throws InvalidAlgorithmParameterException, InvalidKeyException {
      wrappedCipher.init(encryptMode, key, parameterSpec);
    }

    public byte[] doFinal(final byte[] encryptedValue) throws BadPaddingException, IllegalBlockSizeException {
      return wrappedCipher.doFinal(encryptedValue);
    }
  }
}
