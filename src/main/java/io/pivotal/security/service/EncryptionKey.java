package io.pivotal.security.service;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

public class EncryptionKey {
  public static final Charset CHARSET = Charset.defaultCharset();
  private final EncryptionConfiguration encryptionConfiguration;
  private final Key key;

  public EncryptionKey(EncryptionConfiguration encryptionConfiguration, Key key) {
    this.encryptionConfiguration = encryptionConfiguration;
    this.key = key;
  }

  public Encryption encrypt(String value) throws Exception {
    byte[] nonce = generateNonce(this);
    IvParameterSpec parameterSpec = encryptionConfiguration.generateParameterSpec(nonce);
    Cipher encryptionCipher = encryptionConfiguration.getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, getKey(), parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(encrypted, nonce);
  }

  public String decrypt(byte[] encryptedValue, byte[] nonce) throws Exception {
    Cipher decryptionCipher = encryptionConfiguration.getCipher();
    IvParameterSpec ccmParameterSpec = encryptionConfiguration.generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, getKey(), ccmParameterSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }

  // todo make private or GROT, only used in tests
  protected Key getKey() {
    return key;
  }

  private byte[] generateNonce(EncryptionKey encryptionKey) {
    SecureRandom secureRandom = encryptionKey.encryptionConfiguration.getSecureRandom();
    byte[] nonce = new byte[NONCE_SIZE];
    secureRandom.nextBytes(nonce);
    return nonce;
  }
}
