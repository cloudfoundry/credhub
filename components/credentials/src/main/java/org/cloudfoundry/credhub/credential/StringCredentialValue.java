package org.cloudfoundry.credhub.credential;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonValue;
import org.cloudfoundry.credhub.ErrorMessages;

public class StringCredentialValue implements CredentialValue {

  @NotEmpty(message = ErrorMessages.MISSING_VALUE)
  private final String string;

  public StringCredentialValue(final String password) {
    super();
    this.string = password;
  }

  @JsonValue
  public String getStringCredential() {
    return string;
  }


}
