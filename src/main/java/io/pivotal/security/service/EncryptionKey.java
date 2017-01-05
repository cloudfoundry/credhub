package io.pivotal.security.service;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class EncryptionKey {
  private final EncryptionConfiguration encryptionConfiguration;
  private final Key key;

  public EncryptionKey(EncryptionConfiguration encryptionConfiguration, Key key) {
    this.encryptionConfiguration = encryptionConfiguration;
    this.key = key;
  }

  public Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return encryptionConfiguration.getCipher();
  }

  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return encryptionConfiguration.generateParameterSpec(nonce);
  }

  public Key getKey() {
    return key;
  }

  public SecureRandom getSecureRandom() {
    return encryptionConfiguration.getSecureRandom();
  }
}
