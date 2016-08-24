package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;

public interface RequestTranslator<ET extends NamedSecret> {
  ET makeEntity(String name);

  ET populateEntityFromJson(ET namedSecret, DocumentContext documentContext);
}
