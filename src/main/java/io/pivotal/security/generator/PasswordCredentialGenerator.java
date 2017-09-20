package io.pivotal.security.generator;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

// Can't be named PasswordGenerator or Spring won't know how to autowire it.
@Component
public class PasswordCredentialGenerator implements
    CredentialGenerator<StringGenerationParameters, StringCredentialValue> {

  private final PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Autowired
  PasswordCredentialGenerator(PassayStringCredentialGenerator passayStringCredentialGenerator) {
    this.passayStringCredentialGenerator = passayStringCredentialGenerator;
  }

  @Override
  public StringCredentialValue generateCredential(
      StringGenerationParameters stringGenerationParameters) {
    return passayStringCredentialGenerator.generateCredential(stringGenerationParameters);
  }

  @Override
  public StringCredentialValue generateCredential(BaseCredentialGenerateRequest requestBody) {
    final StringGenerationParameters stringGenerationParameters = ((PasswordGenerateRequest) requestBody)
        .getGenerationParameters();
    return this.generateCredential(stringGenerationParameters);
  }
}
