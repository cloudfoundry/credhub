package io.pivotal.security.credential;

public class StringCredential implements Credential {

  private final String string;

  public StringCredential(String password) {
    this.string = password;
  }

  public String getStringSecret() {
    return string;
  }
}
