package io.pivotal.security.request;

public class UserGenerationParameters {

  private StringGenerationParameters usernameGenerationParameters;
  private StringGenerationParameters passwordGenerationParameters;

  public UserGenerationParameters() {
    usernameGenerationParameters = new StringGenerationParameters();
    usernameGenerationParameters.setLength(20);
    usernameGenerationParameters.setExcludeNumber(true);

    passwordGenerationParameters = new StringGenerationParameters();
  }

  public void setUsernameGenerationParameters(StringGenerationParameters parameters) {
    usernameGenerationParameters = parameters;
  }

  public StringGenerationParameters getUsernameGenerationParameters() {
    return usernameGenerationParameters;
  }

  public StringGenerationParameters getPasswordGenerationParameters() {
    return passwordGenerationParameters;
  }
}
