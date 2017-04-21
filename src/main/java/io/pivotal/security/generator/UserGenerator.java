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

  public User generateCredential(UserGenerationParameters generationParameters) {
    StringCredential generatedPassword = stringGenerator.generateCredential(generationParameters.getPasswordGenerationParameters());

    StringCredential generatedUser = null;
    if (generationParameters.getUsernameGenerationParameters() != null) {
      generatedUser = stringGenerator.generateCredential(generationParameters.getUsernameGenerationParameters());
    }

    String username = generatedUser == null ? null : generatedUser.getStringCredential();

    return new User(username, generatedPassword.getStringCredential());
  }
}
