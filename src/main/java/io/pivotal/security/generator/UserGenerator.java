package io.pivotal.security.generator;

import io.pivotal.security.request.UserGenerationParameters;
import io.pivotal.security.secret.StringSecret;
import io.pivotal.security.secret.User;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator {

  private PassayStringSecretGenerator stringGenerator;

  public UserGenerator(PassayStringSecretGenerator stringGenerator) {
    this.stringGenerator = stringGenerator;
  }

  public User generateSecret(UserGenerationParameters generationParameters) {
    StringSecret generatedPassword = stringGenerator.generateSecret(generationParameters.getPasswordGenerationParameters());

    StringSecret generatedUser = null;
    if (generationParameters.getUsernameGenerationParameters() != null) {
      generatedUser = stringGenerator.generateSecret(generationParameters.getUsernameGenerationParameters());
    }

    String username = generatedUser == null ? null : generatedUser.getStringSecret();

    return new User(username, generatedPassword.getStringSecret());
  }
}
