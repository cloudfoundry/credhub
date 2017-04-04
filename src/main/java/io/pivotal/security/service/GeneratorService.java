package io.pivotal.security.service;

import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.secret.SshKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GeneratorService {
  private PassayStringSecretGenerator passwordGenerator;
  private SshGenerator sshGenerator;
  private RsaGenerator rsaGenerator;

  @Autowired
  public GeneratorService(PassayStringSecretGenerator passwordGenerator,
      SshGenerator sshGenerator, RsaGenerator rsaGenerator) {
    this.passwordGenerator = passwordGenerator;
    this.sshGenerator = sshGenerator;
    this.rsaGenerator = rsaGenerator;
  }

  public String generatePassword(PasswordGenerationParameters passwordParameters) {
    return passwordGenerator.generateSecret(passwordParameters).getPassword();
  }

  public SshKey generateSshKeys(SshGenerationParameters generationParameters) {
    return sshGenerator.generateSecret(generationParameters);
  }

  public RsaKey generateRsaKeys(RsaGenerationParameters generationParameters) {
    return rsaGenerator.generateSecret(generationParameters);
  }
}
