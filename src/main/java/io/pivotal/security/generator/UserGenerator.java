package io.pivotal.security.generator;

import io.pivotal.security.credential.User;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator {

  private final UsernameGenerator usernameGenerator;
  private final PasswordCredentialGenerator passwordGenerator;

  @Autowired
  public UserGenerator(UsernameGenerator usernameGenerator, PasswordCredentialGenerator passwordGenerator) {
    this.usernameGenerator = usernameGenerator;
    this.passwordGenerator = passwordGenerator;
  }

  public User generateCredential(String username, StringGenerationParameters passwordParameters) {
    if (username == null) {
      username = usernameGenerator.generateCredential().getStringCredential();
    }

    final String password = passwordGenerator.generateCredential(passwordParameters).getStringCredential();

    return new User(username, password);
  }
}
