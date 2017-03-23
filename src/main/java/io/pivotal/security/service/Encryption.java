package io.pivotal.security.service;

import java.util.UUID;

public class Encryption {
  public final UUID canaryUuid;
  public final byte[] nonce;
  public final byte[] encryptedValue;

  public Encryption(UUID canaryUuid, byte[] encryptedValue, byte[] nonce) {
    this.canaryUuid = canaryUuid;
    this.nonce = nonce;
    this.encryptedValue = encryptedValue;
  }
}
