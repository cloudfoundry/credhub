package io.pivotal.security.validator;

import io.pivotal.security.request.BaseSecretGenerateRequest;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class ValidRegenerateRequestValidator implements ConstraintValidator<ValidRegenerateRequest, BaseSecretGenerateRequest> {
  @Override
  public boolean isValid(BaseSecretGenerateRequest request, ConstraintValidatorContext context) {
    return false;
  }
}
