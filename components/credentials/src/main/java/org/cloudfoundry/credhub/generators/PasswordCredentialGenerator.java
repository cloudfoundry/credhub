package org.cloudfoundry.credhub.generators;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;

// Can't be named PasswordGenerator or Spring won't know how to autowire it.
@Component
public class PasswordCredentialGenerator implements CredentialGenerator<StringCredentialValue> {

  private final PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Autowired
  PasswordCredentialGenerator(final PassayStringCredentialGenerator passayStringCredentialGenerator) {
    super();
    this.passayStringCredentialGenerator = passayStringCredentialGenerator;
  }

  @Override
  public StringCredentialValue generateCredential(final GenerationParameters stringGenerationParameters) {
    return passayStringCredentialGenerator.generateCredential((StringGenerationParameters) stringGenerationParameters);
  }
}
