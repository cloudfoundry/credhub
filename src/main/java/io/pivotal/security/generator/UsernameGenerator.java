package io.pivotal.security.generator;

import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UsernameGenerator {
  private final PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Autowired
  UsernameGenerator(PassayStringCredentialGenerator passayStringCredentialGenerator) {
    this.passayStringCredentialGenerator = passayStringCredentialGenerator;
  }

  public StringCredentialValue generateCredential() {
    final StringGenerationParameters parameters = new StringGenerationParameters();
    parameters.setLength(20);
    parameters.setExcludeNumber(true);

    return passayStringCredentialGenerator.generateCredential(parameters);
  }
}
