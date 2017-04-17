package io.pivotal.security.request;

public class UserSetRequestFields {
  private String username;
  private String password;

  public String getUsername() {
    return username;
  }

  public UserSetRequestFields setUsername(String username) {
    this.username = username;
    return this;
  }

  public String getPassword() {
    return password;
  }

  public UserSetRequestFields setPassword(String password) {
    this.password = password;
    return this;
  }
}
