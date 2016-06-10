package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.model.SecretParameters;
import io.pivotal.security.model.StringGeneratorRequest;
import org.springframework.stereotype.Component;

import java.util.Optional;

import javax.validation.ValidationException;

@Component
public class StringGeneratorRequestTranslator {
  public StringGeneratorRequest validGeneratorRequest(DocumentContext parsed) throws ValidationException {
    SecretParameters secretParameters = new SecretParameters();
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

    StringGeneratorRequest generatorRequest = new StringGeneratorRequest();
    generatorRequest.setParameters(secretParameters);
    generatorRequest.setType(parsed.read("$.type"));

    SecretParameters params = generatorRequest.getParameters();
    boolean isInvalid = params.isExcludeLower()
        && params.isExcludeUpper()
        && params.isExcludeSpecial()
        && params.isExcludeNumber();

    if (isInvalid) {
      throw new ValidationException("error.excludes_all_charsets");
    }
    return generatorRequest;
  }
}
