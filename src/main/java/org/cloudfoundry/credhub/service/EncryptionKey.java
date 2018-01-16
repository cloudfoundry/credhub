package org.cloudfoundry.credhub.service;

import java.security.Key;
import java.util.UUID;

public class EncryptionKey {

  private UUID uuid;
  private final Key key;

  public EncryptionKey(UUID uuid, Key key) {
    this.uuid = uuid;
    this.key = key;
  }

  public EncryptionKey(Key key) {
    this.key = key;
    this.uuid = null;
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
}
