package org.cloudfoundry.credhub.constants;

public enum CipherTypes {
  CCM("AES/CCM/NOPADDING"),
  GCM("AES/GCM/NoPadding");

  private final String cipher;

  CipherTypes(String cipher) {
    this.cipher = cipher;
  }

  public String toString() {
    return cipher;
  }
}
