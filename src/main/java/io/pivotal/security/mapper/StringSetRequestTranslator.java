package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.view.StringSecret;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class StringSetRequestTranslator implements SecretSetterRequestTranslator {

  @Override
  public StringSecret createSecretFromJson(DocumentContext parsed) throws ValidationException {
    String value = parsed.read("$.value");
    if (StringUtils.isEmpty(value)) {
      throw new ValidationException("error.missing_string_secret_value");
    }
    return new StringSecret(value);
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return new NamedStringSecret(name);
  }
}
