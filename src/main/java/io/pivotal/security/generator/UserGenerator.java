package io.pivotal.security.generator;

import io.pivotal.security.request.UserGenerationParameters;
import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.credential.User;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator {

  private PassayStringCredentialGenerator stringGenerator;

  public UserGenerator(PassayStringCredentialGenerator stringGenerator) {
    this.stringGenerator = stringGenerator;
  }

  public User generateSecret(UserGenerationParameters generationParameters) {
    StringCredential generatedPassword = stringGenerator.generateSecret(generationParameters.getPasswordGenerationParameters());

    StringCredential generatedUser = null;
    if (generationParameters.getUsernameGenerationParameters() != null) {
      generatedUser = stringGenerator.generateSecret(generationParameters.getUsernameGenerationParameters());
    }

    String username = generatedUser == null ? null : generatedUser.getStringSecret();

    return new User(username, generatedPassword.getStringSecret());
  }
}
