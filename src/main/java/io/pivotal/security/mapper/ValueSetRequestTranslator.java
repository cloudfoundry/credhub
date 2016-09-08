package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedValueSecret;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.pivotal.security.view.ParameterizedValidationException;

@Component
public class ValueSetRequestTranslator implements RequestTranslator<NamedValueSecret> {

  @Override
  public void populateEntityFromJson(NamedValueSecret namedStringSecret, DocumentContext documentContext) {
    String value = documentContext.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ParameterizedValidationException("error.missing_string_secret_value");
    }
    namedStringSecret.setValue(value);
  }
}
