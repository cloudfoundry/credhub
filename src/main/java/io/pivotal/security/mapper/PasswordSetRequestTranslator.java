package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Set;

import static com.google.common.collect.ImmutableSet.of;

@Component
public class PasswordSetRequestTranslator implements RequestTranslator<NamedPasswordSecret> {

  @Override
  public void populateEntityFromJson(NamedPasswordSecret namedPasswordSecret, DocumentContext documentContext) {
    String value = documentContext.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ParameterizedValidationException("error.missing_string_secret_value");
    }
    namedPasswordSecret.setValue(value);
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['value']", "$['name']", "$['type']", "$['overwrite']");
  }
}
