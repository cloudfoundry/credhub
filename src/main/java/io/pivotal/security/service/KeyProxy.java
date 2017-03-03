package io.pivotal.security.service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

class KeyProxy {
  private static final int SHA_DIGEST = 256;
  private static final int ITERATIONS = 100000;
  private static final int KEYSIZE_BYTES = 16;

  private Key key;
  private String password = null;

  KeyProxy(Key key) {
    this.key = key;
  }

  KeyProxy(String password) {
    this.password = password;
  }

  public Key getKey() {
    return key;
  }

  public Key getKey(byte[] salt){
    if(null == this.password){
      throw new RuntimeException("Password not defined on KeyProxy object");
    }

    return deriveKey(this.password,salt);
  }

  Key deriveKey(String password, byte[] salt) {
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, SHA_DIGEST);

    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      byte[] digest = skf.generateSecret(spec).getEncoded();
      return new SecretKeySpec(digest, 0, KEYSIZE_BYTES, "AES");
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  public void setKey(Key key) {
    this.key = key;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
