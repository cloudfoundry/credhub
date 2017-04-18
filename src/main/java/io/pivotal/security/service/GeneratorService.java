package io.pivotal.security.service;

import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.generator.UserGenerator;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.UserGenerationParameters;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.secret.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GeneratorService {

  private PassayStringSecretGenerator passwordGenerator;
  private SshGenerator sshGenerator;
  private RsaGenerator rsaGenerator;
  private CertificateGenerator certificateGenerator;
  private UserGenerator userGenerator;

  @Autowired
  public GeneratorService(
      PassayStringSecretGenerator passwordGenerator,
      SshGenerator sshGenerator,
      RsaGenerator rsaGenerator,
      CertificateGenerator certificateGenerator,
      UserGenerator userGenerator) {
    this.passwordGenerator = passwordGenerator;
    this.sshGenerator = sshGenerator;
    this.rsaGenerator = rsaGenerator;
    this.certificateGenerator = certificateGenerator;
    this.userGenerator = userGenerator;
  }

  public String generatePassword(StringGenerationParameters passwordParameters) {
    return passwordGenerator.generateSecret(passwordParameters).getStringSecret();
  }

  public SshKey generateSshKeys(SshGenerationParameters generationParameters) {
    return sshGenerator.generateSecret(generationParameters);
  }

  public RsaKey generateRsaKeys(RsaGenerationParameters generationParameters) {
    return rsaGenerator.generateSecret(generationParameters);
  }

  public Certificate generateCertificate(CertificateParameters generationParameters) {
    return certificateGenerator.generateSecret(generationParameters);
  }

  public User generateUser(UserGenerationParameters generationParameters) {
    return userGenerator.generateSecret(generationParameters);
  }
}
