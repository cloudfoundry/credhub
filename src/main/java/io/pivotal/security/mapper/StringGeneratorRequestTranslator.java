package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.StringSecretParameters;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedStringSecret;
import org.springframework.stereotype.Component;

import javax.validation.ValidationException;
import java.util.Optional;

@Component
public class StringGeneratorRequestTranslator implements SecretGeneratorRequestTranslator<StringSecretParameters> {
  @Override
  public StringSecretParameters validRequestParameters(DocumentContext parsed) throws ValidationException {
    StringSecretParameters secretParameters = new StringSecretParameters();
    String secretType = parsed.read("$.type", String.class);
    Optional.ofNullable(secretType).ifPresent(secretParameters::setType);
    Optional.ofNullable(parsed.read("$.parameters.length", Integer.class))
        .ifPresent(secretParameters::setLength);
    Optional.ofNullable(parsed.read("$.parameters.exclude_lower", Boolean.class))
        .ifPresent(secretParameters::setExcludeLower);
    Optional.ofNullable(parsed.read("$.parameters.exclude_upper", Boolean.class))
        .ifPresent(secretParameters::setExcludeUpper);
    Optional.ofNullable(parsed.read("$.parameters.exclude_number", Boolean.class))
        .ifPresent(secretParameters::setExcludeNumber);
    Optional.ofNullable(parsed.read("$.parameters.exclude_special", Boolean.class))
        .ifPresent(secretParameters::setExcludeSpecial);

    if (!secretParameters.isValid()) {
      throw new ValidationException("error.excludes_all_charsets");
    }
    return secretParameters;
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return new NamedStringSecret(name);
  }
}
