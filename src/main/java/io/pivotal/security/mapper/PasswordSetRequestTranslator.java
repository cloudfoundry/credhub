package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class PasswordSetRequestTranslator implements RequestTranslator<NamedPasswordSecret> {

  @Override
  public void populateEntityFromJson(NamedPasswordSecret namedStringSecret, DocumentContext documentContext) {
    String value = documentContext.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ParameterizedValidationException("error.missing_string_secret_value");
    }
    namedStringSecret.setValue(value);
  }
}
