package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SshSecretParametersFactory;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.secret.SshKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.ImmutableSet.of;

@Component
public class SshGeneratorRequestTranslator
    implements RequestTranslator<NamedSshSecret>,
    SecretGeneratorRequestTranslator<SshGenerationParameters, NamedSshSecret> {

  private final SshGenerator sshGenerator;
  private final SshSecretParametersFactory sshSecretParametersFactory;

  @Autowired
  SshGeneratorRequestTranslator(
      SshGenerator sshGenerator,
      SshSecretParametersFactory sshSecretParametersFactory
  ) {
    this.sshGenerator = sshGenerator;
    this.sshSecretParametersFactory = sshSecretParametersFactory;
  }

  @Override
  public SshGenerationParameters validRequestParameters(DocumentContext parsed, NamedSshSecret entity) {
    SshGenerationParameters sshSecretParameters = sshSecretParametersFactory.get();

    Boolean regenerate = parsed.read("$.regenerate", Boolean.class);

    if (Boolean.TRUE.equals(regenerate)) {
      sshSecretParameters.setKeyLength(entity.getKeyLength());
      sshSecretParameters.setSshComment(entity.getComment());
    } else {
      Optional.ofNullable(parsed.read("$.parameters.key_length", Integer.class))
          .ifPresent(sshSecretParameters::setKeyLength);
      Optional.ofNullable(parsed.read("$.parameters.ssh_comment", String.class))
          .ifPresent(sshSecretParameters::setSshComment);

      sshSecretParameters.validate();
    }

    return sshSecretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedSshSecret namedSshSecret,
      DocumentContext documentContext) {
    SshGenerationParameters sshSecretParameters = validRequestParameters(documentContext,
        namedSshSecret);
    final SshKey sshSecret = sshGenerator.generateSecret(sshSecretParameters);

    namedSshSecret.setPublicKey(sshSecret.getPublicKey());
    namedSshSecret.setPrivateKey(sshSecret.getPrivateKey());
  }

  @Override
  public Set<String> getValidKeys() {
    return of(
        "$['type']",
        "$['name']",
        "$['overwrite']",
        "$['regenerate']",
        "$['parameters']",
        "$['parameters']['key_length']",
        "$['parameters']['ssh_comment']"
    );
  }
}
