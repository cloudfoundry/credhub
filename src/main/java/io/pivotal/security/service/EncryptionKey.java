package io.pivotal.security.service;

import java.nio.charset.Charset;
import java.security.Key;

public class EncryptionKey {
  public static final Charset CHARSET = Charset.defaultCharset();
  private final EncryptionConfiguration encryptionConfiguration;
  private final Key key;

  public EncryptionKey(EncryptionConfiguration encryptionConfiguration, Key key) {
    this.encryptionConfiguration = encryptionConfiguration;
    this.key = key;
  }

  // todo make private or GROT, only used in tests
  protected Key getKey() {
    return key;
  }

  public Encryption encrypt(String value) throws Exception {
    return encryptionConfiguration.encrypt(key, value);
  }

  public String decrypt(byte[] encryptedValue, byte[] nonce) throws Exception {
    return encryptionConfiguration.decrypt(key, encryptedValue, nonce);
  }
}
