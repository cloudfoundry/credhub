package org.cloudfoundry.credhub.credential;

import java.util.Objects;

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

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final StringCredentialValue that = (StringCredentialValue) o;
    return Objects.equals(string, that.string);
  }

  @Override
  public int hashCode() {
    return Objects.hash(string);
  }
}
