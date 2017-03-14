package io.pivotal.security.validator;

import io.pivotal.security.request.BaseSecretGenerateRequest;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.List;

public class ValidTypeForGenerationValidator implements ConstraintValidator<ValidTypeForGeneration, BaseSecretGenerateRequest> {
  private List<String> validGenerateTypes = Arrays.asList("password", "certificate", "rsa", "ssh");

  @Override
  public boolean isValid(BaseSecretGenerateRequest request, ConstraintValidatorContext context) {
    if (request.isRegenerate()) return true;
    return validGenerateTypes.contains(request.getType());
  }
}
