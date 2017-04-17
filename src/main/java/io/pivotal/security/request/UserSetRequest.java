package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedUserSecret;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class UserSetRequest extends BaseSecretSetRequest<NamedUserSecret> {
  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private UserSetRequestFields userSetRequestFields;

  public void setUserSetRequestFields(UserSetRequestFields userSetRequestFields) {
    this.userSetRequestFields = userSetRequestFields;
  }

  public UserSetRequestFields getUserSetRequestFields() {
    return userSetRequestFields;
  }

  @Override
  public NamedUserSecret createNewVersion(
      NamedUserSecret existing,
      Encryptor encryptor) {
    return NamedUserSecret.createNewVersion(
        existing,
        getName(),
        getUserSetRequestFields(),
        encryptor,
        getAccessControlEntries());
  }
}
