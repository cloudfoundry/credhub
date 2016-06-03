package io.pivotal.security.validator;

import io.pivotal.security.model.SecretParameters;
import io.pivotal.security.model.StringGeneratorRequest;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class GeneratorRequestValidator implements Validator {

  @Override
  public boolean supports(Class<?> clazz) {
    return StringGeneratorRequest.class.equals(clazz);
  }

  @Override
  public void validate(Object target, Errors errors) {
    StringGeneratorRequest stringGeneratorRequest = (StringGeneratorRequest) target;
    SecretParameters params = stringGeneratorRequest.getParameters();
    boolean isInvalid = params.isExcludeLower() && params.isExcludeUpper() && params.isExcludeSpecial() && params.isExcludeNumber();
    if (isInvalid) {
      errors.reject("error.excludes_all_charsets", "cannot exclude all types of characters");
    }

    final String generatorRequestType = stringGeneratorRequest.getType();
    if (!"value".equals(generatorRequestType)) {
      errors.reject("error.secret_type_invalid", "must specify a valid type");
    }

  }

}
