package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedStringSecret;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class StringSetRequestTranslator implements RequestTranslator<NamedStringSecret> {

  @Override
  public NamedStringSecret makeEntity(String name) {
    return new NamedStringSecret(name);
  }

  @Override
  public NamedStringSecret populateEntityFromJson(NamedStringSecret namedStringSecret, DocumentContext documentContext) {
    String value = documentContext.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ValidationException("error.missing_string_secret_value");
    }
    namedStringSecret.setValue(value);
    return namedStringSecret;
  }
}
