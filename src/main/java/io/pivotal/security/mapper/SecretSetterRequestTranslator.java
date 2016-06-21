package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.model.Secret;

public interface SecretSetterRequestTranslator {
  Secret createSecretFromJson(DocumentContext documentContext);
  NamedSecret makeEntity(String name);
}
