package io.pivotal.security.service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public interface EncryptionService {
  boolean validate(byte[] nonce, byte[] encryptedValue, String value) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException;

  Encryption encrypt(String value) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException;

  String decrypt(byte[] nonce, byte[] encryptedValue) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

  class Encryption {
    public final byte[] nonce;
    public final byte[] encryptedValue;

    public Encryption(byte[] nonce, byte[] encryptedValue) {
      this.nonce = nonce;
      this.encryptedValue = encryptedValue;
    }
  }
}
