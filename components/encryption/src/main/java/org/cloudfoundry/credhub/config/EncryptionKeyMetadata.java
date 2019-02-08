package org.cloudfoundry.credhub.config;

@SuppressWarnings("unused")
public class EncryptionKeyMetadata {
  private String encryptionPassword;
  private boolean active;
  private String encryptionKeyName;


  public String getEncryptionPassword() {
    return encryptionPassword;
  }

  public void setEncryptionPassword(final String encryptionPassword) {
    this.encryptionPassword = encryptionPassword;
  }

  public Boolean isActive() {
    return active;
  }

  public void setActive(final Boolean active) {
    this.active = active;
  }

  public String getEncryptionKeyName() {
    return encryptionKeyName;
  }

  public void setEncryptionKeyName(final String encryptionKeyName) {
    this.encryptionKeyName = encryptionKeyName;
  }

  @Override
  public String toString() {
    return "EncryptionKeyMetadata{" +
      "encryptionPassword='" + encryptionPassword + '\'' +
      ", active=" + active +
      ", encryptionKeyName='" + encryptionKeyName + '\'' +
      '}';
  }
}
