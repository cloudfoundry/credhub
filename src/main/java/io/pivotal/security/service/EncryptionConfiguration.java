package io.pivotal.security.service;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public interface EncryptionConfiguration {
  Provider getProvider();

  SecureRandom getSecureRandom();

  EncryptionKey getActiveKey();

  List<EncryptionKey> getKeys();

  Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;

  IvParameterSpec generateParameterSpec(byte[] nonce);
}
