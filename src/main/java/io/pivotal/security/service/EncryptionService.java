package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CHARSET;

// This class is tested in BCEncryptionServiceTest.

public abstract class EncryptionService {

  abstract SecureRandom getSecureRandom();
  abstract CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;
  abstract IvParameterSpec generateParameterSpec(byte[] nonce);
  abstract KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata);

  public Encryption encrypt(Key key, String value) throws Exception {
    byte[] nonce = generateNonce();
    IvParameterSpec parameterSpec = generateParameterSpec(nonce);
    CipherWrapper encryptionCipher = getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(encrypted, nonce);
  }

  public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
    CipherWrapper decryptionCipher = getCipher();
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

  static class CipherWrapper {
    private Cipher wrappedCipher;

    CipherWrapper(Cipher wrappedCipher) {
      this.wrappedCipher = wrappedCipher;
    }

    public void init(int encryptMode, Key key, IvParameterSpec parameterSpec) throws InvalidAlgorithmParameterException, InvalidKeyException {
      wrappedCipher.init(encryptMode, key, parameterSpec);
    }

    byte[] doFinal(byte[] encryptedValue) throws BadPaddingException, IllegalBlockSizeException {
      return wrappedCipher.doFinal(encryptedValue);
    }
  }
}
