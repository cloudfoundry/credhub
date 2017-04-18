package io.pivotal.security.secret;

public class User {
  private String user;
  private String password;

  public User(String user, String password) {
    this.user = user;
    this.password = password;
  }

  public String getUsername() {
    return user;
  }

  public String getUser() {
    return user;
  }

  public void setUser(String user) {
    this.user = user;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
