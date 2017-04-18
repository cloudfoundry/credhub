package io.pivotal.security.secret;

public class StringSecret implements Secret {

  private final String string;

  public StringSecret(String password) {
    this.string = password;
  }

  public String getStringSecret() {
    return string;
  }
}
