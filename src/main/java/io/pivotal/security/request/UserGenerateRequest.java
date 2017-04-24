package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.User;
import io.pivotal.security.service.GeneratorService;

public class UserGenerateRequest extends BaseCredentialGenerateRequest {
  @JsonProperty("parameters")
  private StringGenerationParameters passwordGenerationParameters = new StringGenerationParameters();

  @JsonProperty("value")
  private UsernameValue value = new UsernameValue();

  @Override
  public void validate() {
    super.validate();
  }

  public BaseCredentialSetRequest generateSetRequest(GeneratorService generatorService) {
    UserSetRequest userSetRequest = new UserSetRequest();
    userSetRequest.setType(getType());
    userSetRequest.setName(getName());
    userSetRequest.setOverwrite(isOverwrite());
    userSetRequest.setAccessControlEntries(getAccessControlEntries());

    User user = generatorService.generateUser(value.getUsername(), passwordGenerationParameters);
    userSetRequest.setUserValue(user);

    return userSetRequest;
  }

  public void setValue(UsernameValue value) {
    this.value = value;
  }

  public void setPasswordGenerationParameters(StringGenerationParameters passwordGenerationParameters) {
    this.passwordGenerationParameters = passwordGenerationParameters;
  }
}
