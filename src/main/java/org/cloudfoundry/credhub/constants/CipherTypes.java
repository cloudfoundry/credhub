package org.cloudfoundry.credhub.constants;

public enum CipherTypes {
  CCM("AES/CCM/NOPADDING"),
  GCM("AES/GCM/NoPadding");

  private final String cipher;

  CipherTypes(final String cipher) {
    this.cipher = cipher;
  }

  @Override
  public String toString() {
    return cipher;
  }
}
