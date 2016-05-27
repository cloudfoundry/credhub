package io.pivotal.security.validator;

import io.pivotal.security.model.GeneratorRequest;
import io.pivotal.security.model.SecretParameters;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class GeneratorRequestValidator implements Validator {

  @Override
  public boolean supports(Class<?> clazz) {
    return GeneratorRequest.class.equals(clazz);
  }

  @Override
  public void validate(Object target, Errors errors) {
    GeneratorRequest generatorRequest = (GeneratorRequest)target;
    SecretParameters params = generatorRequest.getParameters();
    boolean isInvalid = params.isExcludeLower() && params.isExcludeUpper() && params.isExcludeSpecial() && params.isExcludeNumber();
    if (isInvalid) {
      errors.reject("error.excludes_all_charsets", "my custom message");
    }

  }

}
