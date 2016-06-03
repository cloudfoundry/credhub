package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.model.SecretParameters;
import io.pivotal.security.model.StringGeneratorRequest;
import io.pivotal.security.validator.GeneratorRequestValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.MapBindingResult;

import javax.validation.ValidationException;
import java.util.HashMap;
import java.util.Optional;

@Component
public class StringGeneratorRequestTranslator {

  private final GeneratorRequestValidator validator;

  @Autowired
  public StringGeneratorRequestTranslator(GeneratorRequestValidator validator) {
    this.validator = validator;
  }

  public StringGeneratorRequest validGeneratorRequest(DocumentContext parsed) {
    SecretParameters secretParameters = new SecretParameters();
    Optional.ofNullable(parsed.read("$.parameters.length", Integer.class)).ifPresent(secretParameters::setLength);
    Optional.ofNullable(parsed.read("$.parameters.exclude_lower", Boolean.class)).ifPresent(secretParameters::setExcludeLower);
    Optional.ofNullable(parsed.read("$.parameters.exclude_upper", Boolean.class)).ifPresent(secretParameters::setExcludeUpper);
    Optional.ofNullable(parsed.read("$.parameters.exclude_number", Boolean.class)).ifPresent(secretParameters::setExcludeNumber);
    Optional.ofNullable(parsed.read("$.parameters.exclude_special", Boolean.class)).ifPresent(secretParameters::setExcludeSpecial);

    StringGeneratorRequest generatorRequest = new StringGeneratorRequest();
    generatorRequest.setParameters(secretParameters);
    generatorRequest.setType(parsed.read("$.type"));

    Errors result = new MapBindingResult(new HashMap<>(), "");
    validator.validate(generatorRequest, result);
    if (result.hasErrors()) {
      String key = result.getAllErrors().get(0).getCode();
      throw new ValidationException(key);
    }
    return generatorRequest;
  }
}
