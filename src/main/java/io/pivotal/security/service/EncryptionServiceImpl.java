package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.security.*;

@Service
public class EncryptionServiceImpl extends AbstractEncryptionService {

  public static final Charset CHARSET = Charset.defaultCharset();

  private final EncryptionConfiguration encryptionConfiguration;

  @Autowired
  public EncryptionServiceImpl(EncryptionConfiguration encryptionConfiguration) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    this.encryptionConfiguration = encryptionConfiguration;
  }

  @Override
  public Encryption encrypt(String value) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    byte[] nonce = new byte[16];
    encryptionConfiguration.getSecureRandom().nextBytes(nonce);

    IvParameterSpec ivSpec = new IvParameterSpec(nonce);
    Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding", encryptionConfiguration.getProvider());
    encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionConfiguration.getKey(), ivSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(nonce, encrypted);
  }

  @Override
  public String decrypt(byte[] nonce, byte[] encryptedValue) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding", encryptionConfiguration.getProvider());
    IvParameterSpec ivSpec = new IvParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, encryptionConfiguration.getKey(), ivSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }
}
