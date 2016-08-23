package io.pivotal.security.entity;

interface SecretEncryptor {
  String getCachedItem();
  void setCachedItem(String key);

  byte[] getEncryptedValue();
  void setEncryptedValue(byte[] encryptedValue);

  byte[] getNonce();
  void setNonce(byte[] nonce);
}
