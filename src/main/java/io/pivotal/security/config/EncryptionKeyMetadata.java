package io.pivotal.security.config;

public class EncryptionKeyMetadata {
  private String devKey;
  private String encryptionKeyName;
  private boolean active;
  private String password;

  public EncryptionKeyMetadata(String devKey, String encryptionKeyName, boolean active) {
    this(devKey, encryptionKeyName, active, null);
  }

  public EncryptionKeyMetadata(String devKey, String encryptionKeyName, boolean active, String password) {
    this.devKey = devKey;
    this.encryptionKeyName = encryptionKeyName;
    this.active = active;
    this.password = password;
  }

  public EncryptionKeyMetadata() {
  }

  public String getDevKey() {
    return devKey;
  }

  @SuppressWarnings("unused")
  public void setDevKey(String devKey) {
    this.devKey = devKey;
  }

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

  @SuppressWarnings("unused")
  public void setPassword(String password) {
    this.password = password;
  }

  public String getPassword() {
    return password;
  }
}
