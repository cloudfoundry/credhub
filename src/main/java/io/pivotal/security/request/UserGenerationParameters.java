package io.pivotal.security.request;

public class UserGenerationParameters {

  private PasswordGenerationParameters usernameGenerationParameters;
  private PasswordGenerationParameters passwordGenerationParameters;

  public UserGenerationParameters() {
    usernameGenerationParameters = new PasswordGenerationParameters();
    usernameGenerationParameters.setLength(20);
    usernameGenerationParameters.setExcludeNumber(true);

    passwordGenerationParameters = new PasswordGenerationParameters();
  }

  public PasswordGenerationParameters getUsernameGenerationParameters() {
    return usernameGenerationParameters;
  }

  public PasswordGenerationParameters getPasswordGenerationParameters() {
    return passwordGenerationParameters;
  }
}
