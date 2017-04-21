package io.pivotal.security.view;

import io.pivotal.security.credential.Credential;

public class User implements Credential {
  private final String username;
  private final String password;

  public User(String username, String password) {
    this.username = username;
    this.password = password;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }
}
