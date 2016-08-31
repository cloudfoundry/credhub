package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;

public interface RequestTranslator<ET> {
  ET makeEntity(String name);

  Void populateEntityFromJson(ET namedSecret, DocumentContext documentContext);
}
