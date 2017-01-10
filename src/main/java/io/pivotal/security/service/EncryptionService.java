package io.pivotal.security.service;

import org.springframework.stereotype.Service;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

@Service
public class EncryptionService {
  public static final Charset CHARSET = Charset.defaultCharset();

  public Encryption encrypt(EncryptionKey encryptionKey, String value) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    byte[] nonce = generateNonce(encryptionKey);
    IvParameterSpec parameterSpec = encryptionKey.generateParameterSpec(nonce);
    Cipher encryptionCipher = encryptionKey.getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey.getKey(), parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(encrypted, nonce);
  }

  public String decrypt(EncryptionKey encryptionKey, byte[] encryptedValue, byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    Cipher decryptionCipher = encryptionKey.getCipher();
    IvParameterSpec ccmParameterSpec = encryptionKey.generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, encryptionKey.getKey(), ccmParameterSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }

  private byte[] generateNonce(EncryptionKey encryptionKey) {
    SecureRandom secureRandom = encryptionKey.getSecureRandom();
    byte[] nonce = new byte[NONCE_SIZE];
    secureRandom.nextBytes(nonce);
    return nonce;
  }
}
