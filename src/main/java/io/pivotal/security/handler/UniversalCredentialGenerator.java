package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.CredentialGenerator;
import io.pivotal.security.generator.PasswordCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.generator.UserGenerator;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
class UniversalCredentialGenerator {
  private final Map<String, CredentialGenerator> credentialGenerators;

  @Autowired
  public UniversalCredentialGenerator(
      PasswordCredentialGenerator passwordCredentialGenerator,
      UserGenerator userGenerator,
      SshGenerator sshGenerator,
      RsaGenerator rsaGenerator,
      CertificateGenerator certificateGenerator
  ) {
    credentialGenerators = new HashMap<>();
    credentialGenerators.put("password", passwordCredentialGenerator);
    credentialGenerators.put("user", userGenerator);
    credentialGenerators.put("ssh", sshGenerator);
    credentialGenerators.put("rsa", rsaGenerator);
    credentialGenerators.put("certificate", certificateGenerator);
  }

  public CredentialValue generate(BaseCredentialGenerateRequest generateRequest, UserContext userContext) {
    CredentialGenerator generator = credentialGenerators.get(generateRequest.getType());
    return generator.generateCredential(generateRequest.getDomainGenerationParameters(), userContext);
  }
}
