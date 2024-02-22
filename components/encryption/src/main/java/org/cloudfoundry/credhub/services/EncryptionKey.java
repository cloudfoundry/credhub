package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.security.SecureRandom;
import java.util.UUID;

import org.cloudfoundry.credhub.entities.EncryptedValue;

public class EncryptionKey implements RandomNumberGenerator {
  private final Key key;
  private final EncryptionProvider provider;
  private UUID uuid;
  private String encryptionKeyName;

  public EncryptionKey(final EncryptionProvider provider, final UUID uuid, final Key key, final String encryptionKeyName) {
    super();
    this.provider = provider;
    this.uuid = uuid;
    this.key = key;
    this.encryptionKeyName = encryptionKeyName;
  }

  public Key getKey() {
    return key;
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(final UUID uuid) {
    this.uuid = uuid;
  }

  public String decrypt(final byte[] encryptedValue, final byte[] nonce) throws Exception {
    return provider.decrypt(this, encryptedValue, nonce);
  }

  public EncryptedValue encrypt(final String value) throws Exception {
    return provider.encrypt(this, value);
  }

  public EncryptionProvider getProvider() {
    return provider;
  }

  @Override
  public SecureRandom getSecureRandom() {
    return provider.getSecureRandom();
  }

  public String getEncryptionKeyName() {
    return encryptionKeyName;
  }

  public void setEncryptionKeyName(final String encryptionKeyName) {
    this.encryptionKeyName = encryptionKeyName;
  }
}
