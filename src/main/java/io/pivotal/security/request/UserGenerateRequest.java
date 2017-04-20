package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.User;
import io.pivotal.security.service.GeneratorService;

public class UserGenerateRequest extends BaseCredentialGenerateRequest {

  @JsonProperty("parameters")
  private UserGenerationParameters generationParameters;

  @JsonProperty("value")
  private UserValue value = null;

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
    UserSetRequestFields userSetRequestFields = new UserSetRequestFields();

    if (user.getUsername() == null) {
      userSetRequestFields.setUsername(value.getUsername());
    } else {
      userSetRequestFields.setUsername(user.getUsername());
    }

    userSetRequestFields.setPassword(user.getPassword());

    userSetRequest.setUserSetRequestFields(userSetRequestFields);

    return userSetRequest;
  }

  public UserGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  public void setGenerationParameters(
    UserGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  public UserValue getValue() {
    return value;
  }

  public void setValue(UserValue value) {
    this.value = value;
  }
}
