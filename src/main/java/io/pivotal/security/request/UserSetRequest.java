package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.UserCredential;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class UserSetRequest extends BaseCredentialSetRequest<UserCredential> {
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
  public UserCredential createNewVersion(
      UserCredential existing,
      Encryptor encryptor) {
    return UserCredential.createNewVersion(
        existing,
        getName(),
        getUserValue(),
        encryptor
    );
  }
}
