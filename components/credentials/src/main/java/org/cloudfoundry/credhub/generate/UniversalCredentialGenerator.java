package org.cloudfoundry.credhub.generate;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.generators.CertificateGenerator;
import org.cloudfoundry.credhub.generators.CredentialGenerator;
import org.cloudfoundry.credhub.generators.PasswordCredentialGenerator;
import org.cloudfoundry.credhub.generators.RsaGenerator;
import org.cloudfoundry.credhub.generators.SshGenerator;
import org.cloudfoundry.credhub.generators.UserGenerator;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;

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
