package io.pivotal.security.mapper;

import static com.google.common.collect.ImmutableSet.of;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.controller.v1.RsaSecretParametersFactory;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.secret.RsaKey;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RsaGeneratorRequestTranslator
    implements RequestTranslator<NamedRsaSecret>,
    SecretGeneratorRequestTranslator<RsaSecretParameters, NamedRsaSecret> {

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
  public RsaSecretParameters validRequestParameters(DocumentContext parsed, NamedRsaSecret entity) {
    RsaSecretParameters rsaSecretParameters = rsaSecretParametersFactory.get();

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
    RsaSecretParameters rsaSecretParameters = validRequestParameters(documentContext,
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
