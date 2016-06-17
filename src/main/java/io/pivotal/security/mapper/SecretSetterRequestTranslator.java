package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.model.Secret;

public interface SecretSetterRequestTranslator {
  Secret createSecretFromJson(DocumentContext documentContext);
}
