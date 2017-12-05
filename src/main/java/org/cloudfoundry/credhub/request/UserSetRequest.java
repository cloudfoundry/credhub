package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.UserCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class UserSetRequest extends BaseCredentialSetRequest<UserCredentialValue> {
  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private UserCredentialValue userValue;

  public void setUserValue(UserCredentialValue userValue) {
    this.userValue = userValue;
  }

  public UserCredentialValue getUserValue() {
    return userValue;
  }

  @Override
  public UserCredentialValue getCredentialValue() {
    return userValue;
  }
}
