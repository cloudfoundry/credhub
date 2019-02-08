package org.cloudfoundry.credhub.requests;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.UserCredentialValue;

public class UserSetRequest extends BaseCredentialSetRequest<UserCredentialValue> {
  @NotNull(message = "error.missing_value")
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
}
