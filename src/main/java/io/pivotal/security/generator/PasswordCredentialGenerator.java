package io.pivotal.security.generator;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

// Can't be named PasswordGenerator or Spring won't know how to autowire it.
@Component
public class PasswordCredentialGenerator implements CredentialGenerator<StringCredentialValue> {

  private final PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Autowired
  PasswordCredentialGenerator(PassayStringCredentialGenerator passayStringCredentialGenerator) {
    this.passayStringCredentialGenerator = passayStringCredentialGenerator;
  }

  @Override
  public StringCredentialValue generateCredential(GenerationParameters stringGenerationParameters, UserContext userContext) {
    return passayStringCredentialGenerator.generateCredential((StringGenerationParameters) stringGenerationParameters);
  }
}
