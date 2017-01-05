package io.pivotal.security.constants;

public enum KeyUsageExtensions {
  SERVER_AUTH("1.3.6.1.5.5.7.3.1"),
  CLIENT_AUTH("1.3.6.1.5.5.7.3.2"),
  CODE_SIGNING("1.3.6.1.5.5.7.3.3"),
  EMAIL_PROTECTION("1.3.6.1.5.5.7.3.4"),
  TIME_STAMPING("1.3.6.1.5.5.7.3.8");

  private final String extension;

  KeyUsageExtensions(String extension) {
    this.extension = extension;
  }

  public String toString() {
    return extension;
  }

  public static KeyUsageExtensions getExtension(String value) {
    for(KeyUsageExtensions v : values())
      if(v.toString().equalsIgnoreCase(value)) return v;
    throw new IllegalArgumentException();
  }
}
