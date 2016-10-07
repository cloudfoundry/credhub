package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.controller.v1.SshSecretParametersFactory;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.generator.BCSshGenerator;
import io.pivotal.security.view.SshSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.ImmutableSet.of;

@Component
public class SshGeneratorRequestTranslator
    implements RequestTranslator<NamedSshSecret>, SecretGeneratorRequestTranslator<SshSecretParameters> {

  @Autowired
  BCSshGenerator sshGenerator;

  @Autowired
  SshSecretParametersFactory sshSecretParametersFactory;

  public SshSecretParameters validRequestParameters(DocumentContext parsed) {
    SshSecretParameters sshSecretParameters = sshSecretParametersFactory.get();

    Optional.ofNullable(parsed.read("$.parameters.key_length", Integer.class))
        .ifPresent(sshSecretParameters::setKeyLength);
    Optional.ofNullable(parsed.read("$.parameters.ssh_comment", String.class))
        .ifPresent(sshSecretParameters::setSshComment);

    sshSecretParameters.validate();

    return sshSecretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedSshSecret namedSshSecret, DocumentContext documentContext) {
    SshSecretParameters sshSecretParameters = validRequestParameters(documentContext);
    final SshSecret sshSecret = sshGenerator.generateSecret(sshSecretParameters);

    namedSshSecret.setPublicKey(sshSecret.getSshBody().getPublicKey());
    namedSshSecret.setPrivateKey(sshSecret.getSshBody().getPrivateKey());
  }

  @Override
  public Set<String> getValidKeys() {
    return of(
        "$['type']",
        "$['overwrite']",
        "$['parameters']",
        "$['parameters']['key_length']",
        "$['parameters']['ssh_comment']"
    );
  }
}
