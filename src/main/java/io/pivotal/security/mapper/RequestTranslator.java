package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;

public interface RequestTranslator<ET> {
  void populateEntityFromJson(ET namedSecret, DocumentContext documentContext);
}
