package io.pivotal.security.service;

import io.pivotal.security.credential.Certificate;
import io.pivotal.security.credential.RsaKey;
import io.pivotal.security.credential.SshKey;
import io.pivotal.security.credential.User;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.PasswordCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.generator.UserGenerator;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GeneratorService {

  private final PasswordCredentialGenerator passwordGenerator;
  private final SshGenerator sshGenerator;
  private final RsaGenerator rsaGenerator;
  private final CertificateGenerator certificateGenerator;
  private final UserGenerator userGenerator;

  @Autowired
  public GeneratorService(
      PasswordCredentialGenerator passwordGenerator,
      SshGenerator sshGenerator,
      RsaGenerator rsaGenerator,
      CertificateGenerator certificateGenerator,
      UserGenerator userGenerator
  ) {
    this.passwordGenerator = passwordGenerator;
    this.sshGenerator = sshGenerator;
    this.rsaGenerator = rsaGenerator;
    this.certificateGenerator = certificateGenerator;
    this.userGenerator = userGenerator;
  }

  public String generatePassword(StringGenerationParameters passwordParameters) {
    return passwordGenerator.generateCredential(passwordParameters).getStringCredential();
  }

  public SshKey generateSshKeys(SshGenerationParameters generationParameters) {
    return sshGenerator.generateCredential(generationParameters);
  }

  public RsaKey generateRsaKeys(RsaGenerationParameters generationParameters) {
    return rsaGenerator.generateCredential(generationParameters);
  }

  public Certificate generateCertificate(CertificateParameters generationParameters) {
    return certificateGenerator.generateCredential(generationParameters);
  }

  public User generateUser(String username, StringGenerationParameters passwordParameters) {
    return userGenerator.generateCredential(username, passwordParameters);
  }
}
