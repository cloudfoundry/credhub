package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.User;
import io.pivotal.security.service.GeneratorService;

public class UserGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private UserGenerationParameters generationParameters;

  @JsonProperty("value")
  private UsernameValue value = null;

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

    UserGenerationParameters userGenerationParameters = new UserGenerationParameters();

    if (getValue() != null) {
      userGenerationParameters.setUsernameGenerationParameters(null);
    }

    User user = generatorService.generateUser(userGenerationParameters);

    if (user.getUsername() == null) {
      user.setUsername(value.getUsername());
    }

    userSetRequest.setUserValue(user);

    return userSetRequest;
  }

  public UserGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  public void setGenerationParameters(
    UserGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  public UsernameValue getValue() {
    return value;
  }

  public void setValue(UsernameValue value) {
    this.value = value;
  }
}
