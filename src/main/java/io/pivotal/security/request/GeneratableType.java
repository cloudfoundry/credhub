package io.pivotal.security.request;

public enum GeneratableType {
  RSA("rsa"),
  SSH("ssh"),
  CERTIFICATE("certificate"),
  PASSWORD("password");

  private final String type;

  GeneratableType(String type) {
    this.type = type;
  }
}
