package io.pivotal.security.entity;

public interface EncryptedValueContainer {

  byte[] getEncryptedValue();
  void setEncryptedValue(byte[] encryptedValue);

  byte[] getNonce();
  void setNonce(byte[] nonce);
}
