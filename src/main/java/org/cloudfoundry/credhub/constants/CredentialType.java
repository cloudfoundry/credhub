package org.cloudfoundry.credhub.constants;

public enum CredentialType {
  password("password"),
  certificate("certificate"),
  value("value"),
  rsa("rsa"),
  ssh("ssh"),
  json("json"),
  user("user");

  public final String type;

  CredentialType(String type) {
    this.type = type;
  }
}
