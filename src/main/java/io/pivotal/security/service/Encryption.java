package io.pivotal.security.service;

public class Encryption {
  public final byte[] nonce;
  public final byte[] encryptedValue;

  public Encryption(byte[] encryptedValue, byte[] nonce) {
    this.nonce = nonce;
    this.encryptedValue = encryptedValue;
  }
}
