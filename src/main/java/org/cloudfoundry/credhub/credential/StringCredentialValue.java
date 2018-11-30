package org.cloudfoundry.credhub.credential;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonValue;

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
