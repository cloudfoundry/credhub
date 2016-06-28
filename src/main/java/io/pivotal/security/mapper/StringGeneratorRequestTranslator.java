package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.controller.v1.GeneratorRequest;
import io.pivotal.security.controller.v1.StringSecretParameters;
import io.pivotal.security.entity.NamedStringSecret;
import org.springframework.stereotype.Component;

import java.util.Optional;

import javax.validation.ValidationException;

@Component
public class StringGeneratorRequestTranslator implements SecretGeneratorRequestTranslator {
  @Override
  public GeneratorRequest<StringSecretParameters> validGeneratorRequest(DocumentContext parsed) throws ValidationException {
    StringSecretParameters secretParameters = new StringSecretParameters();
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

    GeneratorRequest<StringSecretParameters> generatorRequest = new GeneratorRequest<>();
    generatorRequest.setParameters(secretParameters);
    generatorRequest.setType(parsed.read("$.type"));

    StringSecretParameters params = generatorRequest.getParameters();
    if (!params.isValid()) {
      throw new ValidationException("error.excludes_all_charsets");
    }
    return generatorRequest;
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return new NamedStringSecret(name);
  }
}
