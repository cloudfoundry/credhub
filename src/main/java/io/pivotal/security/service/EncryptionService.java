package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

@Service
public class EncryptionService {
  public static final Charset CHARSET = Charset.defaultCharset();
  private final EncryptionConfiguration encryptionConfiguration;

  @Autowired
  public EncryptionService(EncryptionConfiguration encryptionConfiguration) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    this.encryptionConfiguration = encryptionConfiguration;
  }

  public Encryption encrypt(String value) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    byte[] nonce = generateNonce();
    IvParameterSpec parameterSpec = encryptionConfiguration.generateParameterSpec(nonce);
    Cipher encryptionCipher = encryptionConfiguration.getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionConfiguration.getKey(), parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(encrypted, nonce);
  }

  public String decrypt(byte[] encryptedValue, byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    Cipher decryptionCipher = encryptionConfiguration.getCipher();
    IvParameterSpec ccmParameterSpec = encryptionConfiguration.generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, encryptionConfiguration.getKey(), ccmParameterSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }

  private byte[] generateNonce() {
    SecureRandom secureRandom = encryptionConfiguration.getSecureRandom();
    byte[] nonce = new byte[encryptionConfiguration.getNonceLength()];
    secureRandom.nextBytes(nonce);
    return nonce;
  }
}
