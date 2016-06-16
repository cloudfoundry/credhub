package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.model.GeneratorRequest;

import javax.validation.ValidationException;

public interface SecretGeneratorRequestTranslator {
  GeneratorRequest validGeneratorRequest(DocumentContext parsed) throws ValidationException;
}
