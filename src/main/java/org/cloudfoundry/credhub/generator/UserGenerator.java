package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.CryptSaltFactory;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator implements CredentialGenerator<UserCredentialValue> {

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

  public UserCredentialValue generateCredential(GenerationParameters p) {
    StringGenerationParameters params = (StringGenerationParameters) p;
    String username = params.getUsername();
    if (username == null) {
      username = usernameGenerator.generateCredential().getStringCredential();
    }

    String password = passwordGenerator.generateCredential(params).getStringCredential();

    return new UserCredentialValue(username, password,
        cryptSaltFactory.generateSalt(password));
  }
}
