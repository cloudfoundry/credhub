package io.pivotal.security.service;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.service.EncryptionKeyService.CHARSET;

public abstract class EncryptionService {
  protected abstract Provider getProvider();
  protected abstract SecureRandom getSecureRandom();
  protected abstract Key getActiveKey();
  protected abstract List<Key> getKeys();
  protected abstract Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;
  protected abstract IvParameterSpec generateParameterSpec(byte[] nonce);

  public Encryption encrypt(Key key, String value) throws Exception {
    byte[] nonce = generateNonce();
    IvParameterSpec parameterSpec = generateParameterSpec(nonce);
    Cipher encryptionCipher = getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(encrypted, nonce);
  }

  public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
    Cipher decryptionCipher = getCipher();
    IvParameterSpec ccmParameterSpec = generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, key, ccmParameterSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }

  private byte[] generateNonce() {
    SecureRandom secureRandom = getSecureRandom();
    byte[] nonce = new byte[NONCE_SIZE];
    secureRandom.nextBytes(nonce);
    return nonce;
  }
}
