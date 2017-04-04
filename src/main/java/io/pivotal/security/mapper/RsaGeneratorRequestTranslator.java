package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.RsaSecretParametersFactory;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.secret.RsaKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.ImmutableSet.of;

@Component
public class RsaGeneratorRequestTranslator
    implements RequestTranslator<NamedRsaSecret>,
    SecretGeneratorRequestTranslator<RsaGenerationParameters, NamedRsaSecret> {

  private final RsaGenerator rsaGenerator;
  private final RsaSecretParametersFactory rsaSecretParametersFactory;

  @Autowired
  RsaGeneratorRequestTranslator(
      RsaGenerator rsaGenerator,
      RsaSecretParametersFactory rsaSecretParametersFactory
  ) {
    this.rsaGenerator = rsaGenerator;
    this.rsaSecretParametersFactory = rsaSecretParametersFactory;
  }

  @Override
  public RsaGenerationParameters validRequestParameters(DocumentContext parsed, NamedRsaSecret entity) {
    RsaGenerationParameters rsaSecretParameters = rsaSecretParametersFactory.get();

    Boolean regenerate = parsed.read("$.regenerate", Boolean.class);
    if (Boolean.TRUE.equals(regenerate)) {
      rsaSecretParameters.setKeyLength(entity.getKeyLength());
    } else {
      Optional.ofNullable(parsed.read("$.parameters.key_length", Integer.class))
          .ifPresent(rsaSecretParameters::setKeyLength);

      rsaSecretParameters.validate();
    }

    return rsaSecretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedRsaSecret namedRsaSecret,
      DocumentContext documentContext) {
    RsaGenerationParameters rsaSecretParameters = validRequestParameters(documentContext,
        namedRsaSecret);
    final RsaKey rsaSecret = rsaGenerator.generateSecret(rsaSecretParameters);

    namedRsaSecret.setPrivateKey(rsaSecret.getPrivateKey());
    namedRsaSecret.setPublicKey(rsaSecret.getPublicKey());
  }

  @Override
  public Set<String> getValidKeys() {
    return of(
        "$['type']",
        "$['name']",
        "$['regenerate']",
        "$['overwrite']",
        "$['parameters']",
        "$['parameters']['key_length']"
    );
  }
}
