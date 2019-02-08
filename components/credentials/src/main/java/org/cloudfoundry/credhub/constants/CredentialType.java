package org.cloudfoundry.credhub.constants;

public enum CredentialType {
  PASSWORD("password"),
  CERTIFICATE("certificate"),
  VALUE("value"),
  RSA("rsa"),
  SSH("ssh"),
  JSON("json"),
  USER("user");

  public final String type;

  CredentialType(final String type) {
    this.type = type.toUpperCase();
  }
}
