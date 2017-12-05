package org.cloudfoundry.credhub.config;

public class EncryptionKeyMetadata {

  private String encryptionKeyName;
  private String encryptionPassword;
  private boolean active;

  public String getEncryptionKeyName() {
    return encryptionKeyName;
  }

  @SuppressWarnings("unused")
  public void setEncryptionKeyName(String encryptionKeyName) {
    this.encryptionKeyName = encryptionKeyName;
  }

  public boolean isActive() {
    return active;
  }

  @SuppressWarnings("unused")
  public void setActive(boolean active) {
    this.active = active;
  }

  public String getEncryptionPassword() {
    return encryptionPassword;
  }

  @SuppressWarnings("unused")
  public void setEncryptionPassword(String encryptionPassword) {
    this.encryptionPassword = encryptionPassword;
  }
}
