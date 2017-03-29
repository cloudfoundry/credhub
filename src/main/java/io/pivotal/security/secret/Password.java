package io.pivotal.security.secret;

public class Password implements Secret {

  private final String password;

  public Password(String password) {
    this.password = password;
  }

  public String getPassword() {
    return password;
  }
}
