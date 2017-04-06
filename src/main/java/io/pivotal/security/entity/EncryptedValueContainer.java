package io.pivotal.security.entity;

import java.util.UUID;

public interface EncryptedValueContainer<Z> {

  byte[] getEncryptedValue();

  Z setEncryptedValue(byte[] encryptedValue);

  byte[] getNonce();

  Z setNonce(byte[] nonce);

  UUID getEncryptionKeyUuid();

  Z setEncryptionKeyUuid(UUID encryptionKeyUuid);
}
