package org.cloudfoundry.credhub.generator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.CryptSaltFactory;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;

@Component
public class UserGenerator implements CredentialGenerator<UserCredentialValue> {

  private final UsernameGenerator usernameGenerator;
  private final PasswordCredentialGenerator passwordGenerator;
  private final CryptSaltFactory cryptSaltFactory;

  @Autowired
  public UserGenerator(
    final UsernameGenerator usernameGenerator,
    final PasswordCredentialGenerator passwordGenerator,
    final CryptSaltFactory cryptSaltFactory
  ) {
    super();
    this.usernameGenerator = usernameGenerator;
    this.passwordGenerator = passwordGenerator;
    this.cryptSaltFactory = cryptSaltFactory;
  }

  @Override
  public UserCredentialValue generateCredential(final GenerationParameters p) {
    final StringGenerationParameters params = (StringGenerationParameters) p;
    String username = params.getUsername();
    if (username == null) {
      username = usernameGenerator.generateCredential().getStringCredential();
    }

    final String password = passwordGenerator.generateCredential(params).getStringCredential();

    return new UserCredentialValue(username, password,
      cryptSaltFactory.generateSalt(password));
  }
}
