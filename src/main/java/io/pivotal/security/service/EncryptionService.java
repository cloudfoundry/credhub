package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.entity.EncryptionKeyCanary;

import javax.crypto.AEADBadTagException;
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

  boolean isMatchingCanary(KeyProxy encryptionKeyProxy, EncryptionKeyCanary canary) {
    Key key = (canary.getSalt() != null) ?
        encryptionKeyProxy.getKey(canary.getSalt()) :
        encryptionKeyProxy.getKey();

    return isMatchingCanary(key, canary);
  }

  protected boolean isMatchingCanary(Key encryptionKey, EncryptionKeyCanary canary) {
    String plaintext;

    try {
      plaintext = decrypt(encryptionKey, canary.getEncryptedValue(), canary.getNonce());
      return EncryptionKeyCanaryMapper.CANARY_VALUE.equals(plaintext);
    } catch (AEADBadTagException e) {
      // dev_internal key was wrong
    } catch (IllegalBlockSizeException e) {
      // Our guess(es) at "HSM key was wrong":
      if (!e.getMessage().contains("returns 0x40")) {
        throw new RuntimeException(e);
      }
      // Could not process input data: function 'C_Decrypt' returns 0x40
    } catch (BadPaddingException e) {
      // Our guess(es) at "DSM key was wrong":
      if (!e.getMessage().contains("rv=48")) {
        throw new RuntimeException(e);
      }
      // javax.crypto.BadPaddingException: Decrypt error: rv=48
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return false;
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
