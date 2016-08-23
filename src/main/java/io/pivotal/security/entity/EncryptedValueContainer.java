package io.pivotal.security.entity;

interface EncryptedValueContainer {

  byte[] getEncryptedValue();
  void setEncryptedValue(byte[] encryptedValue);

  byte[] getNonce();
  void setNonce(byte[] nonce);
}
