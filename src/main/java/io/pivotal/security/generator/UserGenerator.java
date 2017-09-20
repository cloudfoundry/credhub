package io.pivotal.security.generator;

import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator implements
    CredentialGenerator<StringGenerationParameters, UserCredentialValue> {

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

  public UserCredentialValue generateCredential(StringGenerationParameters passwordParameters) {

    if (passwordParameters.getUsername() == null) {
      String username = usernameGenerator.generateCredential().getStringCredential();
      passwordParameters.setUsername(username);
    }

    final String password = passwordGenerator.generateCredential(passwordParameters)
        .getStringCredential();

    return new UserCredentialValue(passwordParameters.getUsername(), password,
        cryptSaltFactory.generateSalt(password));
  }

  @Override
  public UserCredentialValue generateCredential(BaseCredentialGenerateRequest requestBody) {
    final StringGenerationParameters userGenerationParameters = ((UserGenerateRequest) requestBody)
        .getUserCredentialGenerationParameters();
    return this.generateCredential(userGenerationParameters);
  }
}
