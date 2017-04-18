package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.secret.User;
import io.pivotal.security.service.GeneratorService;

public class UserGenerateRequest extends BaseSecretGenerateRequest {

  @JsonProperty("parameters")
  private UserGenerationParameters generationParameters;

  @Override
  public void validate() {
    super.validate();
  }

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    UserSetRequest userSetRequest = new UserSetRequest();
    userSetRequest.setType(getType());
    userSetRequest.setName(getName());
    userSetRequest.setOverwrite(isOverwrite());
    userSetRequest.setAccessControlEntries(getAccessControlEntries());

    User user = generatorService.generateUser(new UserGenerationParameters());
    UserSetRequestFields userSetRequestFields = new UserSetRequestFields();
    userSetRequestFields.setUsername(user.getUsername());
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
}
