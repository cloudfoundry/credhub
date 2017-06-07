package io.pivotal.security.service;

import java.util.Arrays;
import java.util.UUID;

public class Encryption {

  public final UUID canaryUuid;
  public final byte[] nonce;
  public final byte[] encryptedValue;

  public Encryption(UUID canaryUuid, byte[] encryptedValue, byte[] nonce) {
    this.canaryUuid = canaryUuid;
    this.nonce = nonce == null ? null : nonce.clone();
    this.encryptedValue = encryptedValue == null ? null : encryptedValue.clone();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Encryption)) return false;

    Encryption that = (Encryption) o;

    if (canaryUuid != null ? !canaryUuid.equals(that.canaryUuid) : that.canaryUuid != null) return false;
    if (!Arrays.equals(nonce, that.nonce)) return false;
    return Arrays.equals(encryptedValue, that.encryptedValue);
  }

  @Override
  public int hashCode() {
    int result = canaryUuid != null ? canaryUuid.hashCode() : 0;
    result = 31 * result + Arrays.hashCode(nonce);
    result = 31 * result + Arrays.hashCode(encryptedValue);
    return result;
  }
}
