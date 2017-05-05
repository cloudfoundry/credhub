package io.pivotal.security.generator;

import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator {

  private final UsernameGenerator usernameGenerator;
  private final PasswordCredentialGenerator passwordGenerator;
  private final CryptSaltFactory cryptSaltFactory;

  @Autowired
  public UserGenerator(
      UsernameGenerator usernameGenerator,
      PasswordCredentialGenerator passwordGenerator,
      CryptSaltFactory cryptSaltFactory
  ) {
    this.usernameGenerator = usernameGenerator;
    this.passwordGenerator = passwordGenerator;
    this.cryptSaltFactory = cryptSaltFactory;
  }

  public UserCredentialValue generateCredential(String username, StringGenerationParameters passwordParameters) {
    if (username == null) {
      username = usernameGenerator.generateCredential().getStringCredential();
    }

    final String password = passwordGenerator.generateCredential(passwordParameters).getStringCredential();

    return new UserCredentialValue(username, password, cryptSaltFactory.generateSalt(password));
  }
}
