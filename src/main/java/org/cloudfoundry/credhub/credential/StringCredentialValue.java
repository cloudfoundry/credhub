package org.cloudfoundry.credhub.credential;

import com.fasterxml.jackson.annotation.JsonValue;

import javax.validation.constraints.NotEmpty;

public class StringCredentialValue implements CredentialValue {

  @NotEmpty(message = "error.missing_value")
  private final String string;

  public StringCredentialValue(String password) {
    this.string = password;
  }

  @JsonValue
  public String getStringCredential() {
    return string;
  }


}
