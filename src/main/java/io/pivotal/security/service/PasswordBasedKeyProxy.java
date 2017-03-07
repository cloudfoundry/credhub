package io.pivotal.security.service;

import io.pivotal.security.entity.EncryptionKeyCanary;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import static io.pivotal.security.constants.EncryptionConstants.ITERATIONS;
import static io.pivotal.security.constants.EncryptionConstants.KEY_BIT_LENGTH;
import static io.pivotal.security.constants.EncryptionConstants.SALT_SIZE;

class PasswordBasedKeyProxy extends DefaultKeyProxy implements KeyProxy {
  private String password = null;
  private byte[] salt;

  PasswordBasedKeyProxy(String password, EncryptionService encryptionService) {
    super(null, encryptionService);
    this.password = password;
  }

  protected Key deriveKey(String password, byte[] salt) {
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BIT_LENGTH);

    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384");
      return skf.generateSecret(spec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public byte[] getSalt() {
    return salt;
  }

  @Override
  public boolean matchesCanary(EncryptionKeyCanary canary) {
    Key key = deriveKey(password, canary.getSalt());

    boolean result = super.matchesCanary(key, canary);
    if (result) {
      setKey(key);
    }
    return result;
  }

  @Override
  public Key getKey() {
    if (super.getKey() == null) {
      salt = generateSalt();
      setKey(deriveKey(password, salt));
    }

    return super.getKey();
  }

  protected byte[] generateSalt() {
    SecureRandom sr;
    byte[] salt = new byte[SALT_SIZE];
    try {
      sr = SecureRandom.getInstance("SHA1PRNG");
      sr.nextBytes(salt);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    sr.nextBytes(salt);
    return salt;
  }
}
