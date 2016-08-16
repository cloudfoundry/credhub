package io.pivotal.security.service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public abstract class AbstractEncryptionService implements EncryptionService {
  public boolean validate(byte[] nonce, byte[] encryptedValue, String value) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    return nonce != null && Objects.equals(value, decrypt(nonce, encryptedValue));
  }
}
