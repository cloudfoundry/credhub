package org.cloudfoundry.credhub.requests;

import java.util.Objects;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.UserCredentialValue;

public class UserSetRequest extends BaseCredentialSetRequest<UserCredentialValue> {
  @NotNull(message = ErrorMessages.MISSING_VALUE)
  @Valid
  @JsonProperty("value")
  private UserCredentialValue userValue;

  public UserCredentialValue getUserValue() {
    return userValue;
  }

  public void setUserValue(final UserCredentialValue userValue) {
    this.userValue = userValue;
  }

  @Override
  public UserCredentialValue getCredentialValue() {
    return userValue;
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final UserSetRequest that = (UserSetRequest) o;
    return Objects.equals(userValue, that.userValue);
  }

  @Override
  public int hashCode() {
    return Objects.hash(userValue);
  }
}
