package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.GeneratorRequest;
import io.pivotal.security.entity.NamedSecret;

import javax.validation.ValidationException;

public interface SecretGeneratorRequestTranslator {
  GeneratorRequest validGeneratorRequest(DocumentContext parsed) throws ValidationException;

  NamedSecret makeEntity(String name);
}
