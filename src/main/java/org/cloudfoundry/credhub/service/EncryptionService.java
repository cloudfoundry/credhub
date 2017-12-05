package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptedValue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.UUID;

import static org.cloudfoundry.credhub.constants.EncryptionConstants.NONCE_SIZE;
import static org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper.CHARSET;

// This class is tested in BCEncryptionServiceTest.

public abstract class EncryptionService {

  abstract CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;

  abstract AlgorithmParameterSpec generateParameterSpec(byte[] nonce);

  abstract KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata);

  public abstract SecureRandom getSecureRandom();

  public EncryptedValue encrypt(UUID canaryUuid, Key key, String value) throws Exception {
    byte[] nonce = generateNonce();
    AlgorithmParameterSpec parameterSpec = generateParameterSpec(nonce);
    CipherWrapper encryptionCipher = getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new EncryptedValue(canaryUuid, encrypted, nonce);
  }

  public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
    CipherWrapper decryptionCipher = getCipher();
    AlgorithmParameterSpec parameterSpec = generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

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

    public void init(int encryptMode, Key key, AlgorithmParameterSpec parameterSpec)
        throws InvalidAlgorithmParameterException, InvalidKeyException {
      wrappedCipher.init(encryptMode, key, parameterSpec);
    }

    byte[] doFinal(byte[] encryptedValue) throws BadPaddingException, IllegalBlockSizeException {
      return wrappedCipher.doFinal(encryptedValue);
    }
  }
}
