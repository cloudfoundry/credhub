package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.GeneratorRequest;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.Secret;

public class RequestTranslatorWithGeneration implements SecretSetterRequestTranslator {
  private final SecretGenerator secretGenerator;
  private final SecretGeneratorRequestTranslator generatorRequestTranslator;

  public RequestTranslatorWithGeneration(SecretGenerator secretGenerator, SecretGeneratorRequestTranslator generatorRequestTranslator) {
    this.secretGenerator = secretGenerator;
    this.generatorRequestTranslator = generatorRequestTranslator;
  }

  @Override
  public Secret createSecretFromJson(DocumentContext documentContext) {
    GeneratorRequest generatorRequest = generatorRequestTranslator.validGeneratorRequest(documentContext);

    return secretGenerator.generateSecret(generatorRequest.getParameters());
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return generatorRequestTranslator.makeEntity(name);
  }
}
