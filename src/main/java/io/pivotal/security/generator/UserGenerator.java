package io.pivotal.security.generator;

import io.pivotal.security.request.UserGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.secret.User;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator {

  private PassayStringSecretGenerator stringGenerator;

  public UserGenerator(PassayStringSecretGenerator stringGenerator) {
    this.stringGenerator = stringGenerator;
  }

  public User generateSecret(UserGenerationParameters generationParameters) {
    Password password = stringGenerator.generateSecret(generationParameters.getPasswordGenerationParameters());

    Password user = stringGenerator.generateSecret(generationParameters.getUsernameGenerationParameters());

    return new User(user.getPassword(), password.getPassword());
  }
}
