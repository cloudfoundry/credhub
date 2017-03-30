package io.pivotal.security.service;

import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.request.PasswordGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GeneratorService {
  private PassayStringSecretGenerator passwordGenerator;

  @Autowired
  public GeneratorService(PassayStringSecretGenerator passwordGenerator) {
    this.passwordGenerator = passwordGenerator;
  }

  public String generatePassword(PasswordGenerationParameters passwordParameters) {
    return passwordGenerator.generateSecret(passwordParameters).getPassword();
  }
}
