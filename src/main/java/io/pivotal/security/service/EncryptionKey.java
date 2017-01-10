package io.pivotal.security.service;

import java.nio.charset.Charset;
import java.security.Key;

public class EncryptionKey {
  public static final Charset CHARSET = Charset.defaultCharset();
  private final EncryptionService encryptionService;
  private final Key key;

  public EncryptionKey(EncryptionService encryptionService, Key key) {
    this.encryptionService = encryptionService;
    this.key = key;
  }

  // todo make private or GROT, only used in tests
  protected Key getKey() {
    return key;
  }

  public Encryption encrypt(String value) throws Exception {
    return encryptionService.encrypt(key, value);
  }

  public String decrypt(byte[] encryptedValue, byte[] nonce) throws Exception {
    return encryptionService.decrypt(key, encryptedValue, nonce);
  }
}
