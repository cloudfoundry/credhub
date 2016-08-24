package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.RequestParameters;

import javax.validation.ValidationException;

public interface SecretGeneratorRequestTranslator<T extends RequestParameters> {
  T validRequestParameters(DocumentContext parsed) throws ValidationException;
}
