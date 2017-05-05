package io.pivotal.security.credential;

import com.fasterxml.jackson.annotation.JsonValue;
import org.hibernate.validator.constraints.NotEmpty;

public class StringCredential implements CredentialValue {

  @NotEmpty(message = "error.missing_value")
  private final String string;

  public StringCredential(String password) {
    this.string = password;
  }

  @JsonValue
  public String getStringCredential() {
    return string;
  }
}
