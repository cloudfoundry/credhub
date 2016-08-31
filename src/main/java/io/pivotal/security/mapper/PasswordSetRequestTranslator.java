package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedPasswordSecret;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class PasswordSetRequestTranslator implements RequestTranslator<NamedPasswordSecret> {

  @Override
  public void populateEntityFromJson(NamedPasswordSecret namedStringSecret, DocumentContext documentContext) {
    String value = documentContext.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ValidationException("error.missing_string_secret_value");
    }
    namedStringSecret.setValue(value);
  }
}
