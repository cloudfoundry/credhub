package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import static com.google.common.collect.ImmutableSet.of;

import java.util.Set;

@Component
public class StringSetRequestTranslator implements RequestTranslator<NamedStringSecret> {

  @Override
  public void populateEntityFromJson(NamedStringSecret namedStringSecret, DocumentContext documentContext) {
    String value = documentContext.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ParameterizedValidationException("error.missing_string_secret_value");
    }
    namedStringSecret.setValue(value);
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['value']", "$['name']", "$['type']", "$['overwrite']");
  }
}
