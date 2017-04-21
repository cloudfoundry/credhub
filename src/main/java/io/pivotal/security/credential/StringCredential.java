package io.pivotal.security.credential;

import com.fasterxml.jackson.annotation.JsonValue;

public class StringCredential implements Credential {

  private final String string;

  public StringCredential(String password) {
    this.string = password;
  }

  @JsonValue
  public String getStringCredential() {
    return string;
  }
}
