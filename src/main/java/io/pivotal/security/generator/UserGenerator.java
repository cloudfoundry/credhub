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
    StringSecret stringSecret = stringGenerator.generateSecret(generationParameters.getPasswordGenerationParameters());

    StringSecret user = stringGenerator.generateSecret(generationParameters.getUsernameGenerationParameters());

    return new User(user.getStringSecret(), stringSecret.getStringSecret());
  }
}
