package org.cloudfoundry.credhub.handler;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.generator.CertificateGenerator;
import org.cloudfoundry.credhub.generator.CredentialGenerator;
import org.cloudfoundry.credhub.generator.PasswordCredentialGenerator;
import org.cloudfoundry.credhub.generator.RsaGenerator;
import org.cloudfoundry.credhub.generator.SshGenerator;
import org.cloudfoundry.credhub.generator.UserGenerator;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;

@Component
public class UniversalCredentialGenerator {
  private final Map<String, CredentialGenerator> credentialGenerators;

  @Autowired
  public UniversalCredentialGenerator(
    final PasswordCredentialGenerator passwordCredentialGenerator,
    final UserGenerator userGenerator,
    final SshGenerator sshGenerator,
    final RsaGenerator rsaGenerator,
    final CertificateGenerator certificateGenerator
  ) {
    super();
    credentialGenerators = new HashMap<>();
    credentialGenerators.put("password", passwordCredentialGenerator);
    credentialGenerators.put("user", userGenerator);
    credentialGenerators.put("ssh", sshGenerator);
    credentialGenerators.put("rsa", rsaGenerator);
    credentialGenerators.put("certificate", certificateGenerator);
  }

  public CredentialValue generate(final BaseCredentialGenerateRequest generateRequest) {
    final CredentialGenerator generator = credentialGenerators.get(generateRequest.getType());
    return generator.generateCredential(generateRequest.getGenerationParameters());
  }
}
