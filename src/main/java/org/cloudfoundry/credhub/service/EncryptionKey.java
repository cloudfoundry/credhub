package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.entity.EncryptedValue;

import java.security.Key;
import java.security.SecureRandom;
import java.util.UUID;

public class EncryptionKey implements RandomNumberGenerator {

  private EncryptionService service;
  private UUID uuid;
  private final Key key;

  public EncryptionKey(EncryptionService service, UUID uuid, Key key) {
    this.service = service;
    this.uuid = uuid;
    this.key = key;
  }

  public Key getKey() {
    return key;
  }

  public UUID getUuid() {
    return uuid;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public String decrypt(byte[] encryptedValue, byte[] nonce) throws Exception {
    return service.decrypt(this, encryptedValue, nonce);
  }

  public EncryptedValue encrypt(String value) throws Exception {
    return service.encrypt(this, value);
  }

  public EncryptionService getService() {
    return service;
  }

  public void reconnect(Exception e) throws Exception {
    service.reconnect(e);
  }

  @Override
  public SecureRandom getSecureRandom() {
    return service.getSecureRandom();
  }
}
