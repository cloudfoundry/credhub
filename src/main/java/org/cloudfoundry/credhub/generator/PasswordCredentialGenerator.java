package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
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
  public StringCredentialValue generateCredential(GenerationParameters stringGenerationParameters) {
    return passayStringCredentialGenerator.generateCredential((StringGenerationParameters) stringGenerationParameters);
  }
}
