package io.pivotal.security.entity;

import java.util.UUID;

public interface EncryptedValueContainer {

  byte[] getEncryptedValue();

  void setEncryptedValue(byte[] encryptedValue);

  byte[] getNonce();

  void setNonce(byte[] nonce);

  UUID getEncryptionKeyUuid();

  void setEncryptionKeyUuid(UUID encryptionKeyUuid);
}
