package io.pivotal.security.generator;

import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

// Can't be named PasswordGenerator or Spring won't know how to autowire it.
@Component
public class PasswordCredentialGenerator implements CredentialGenerator<StringGenerationParameters, StringCredential> {
  private final PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Autowired
  PasswordCredentialGenerator(PassayStringCredentialGenerator passayStringCredentialGenerator) {
    this.passayStringCredentialGenerator = passayStringCredentialGenerator;
  }

  @Override
  public StringCredential generateCredential(StringGenerationParameters stringGenerationParameters) {
    return passayStringCredentialGenerator.generateCredential(stringGenerationParameters);
  }
}
