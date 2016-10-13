package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.RequestParameters;

public interface SecretGeneratorRequestTranslator<T extends RequestParameters, ET> {
  T validRequestParameters(DocumentContext parsed, ET entity);
}
