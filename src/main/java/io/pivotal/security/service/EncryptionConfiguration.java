package io.pivotal.security.service;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

public interface EncryptionConfiguration {
  Provider getProvider();

  SecureRandom getSecureRandom();

  Key getKey();

  Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;

  IvParameterSpec generateParameterSpec(byte[] nonce);

  int getNonceLength();
}
