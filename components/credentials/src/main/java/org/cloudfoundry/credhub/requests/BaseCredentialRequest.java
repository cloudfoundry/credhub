package org.cloudfoundry.credhub.requests;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

public abstract class BaseCredentialRequest {
  // '.', ':', '(', ')','[',']','+'
  public static final String HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH
    = "^(/|(?>(?:/?[^/]+))*)$";
  private static final String ONLY_VALID_CHARACTERS_IN_NAME = "^[a-zA-Z0-9-_/.:,()\\[\\]+]*$";
  private static final String IS_NOT_EMPTY = "^(.|\n){2,}$";

  @NotEmpty(message = "error.missing_name")
  @Pattern.List({
    @Pattern(regexp = HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH, message = "error.credential.invalid_slash_in_name"),
    @Pattern(regexp = ONLY_VALID_CHARACTERS_IN_NAME, message = "error.credential.invalid_character_in_name"),
    @Pattern(regexp = IS_NOT_EMPTY, message = "error.missing_name"),
  })
  private String name;
  private String type;

  public String getType() {
    return type;
  }

  public void setType(final String type) {
    this.type = type.toLowerCase();
  }

  public String getName() {
    return name;
  }

  public void setName(final String name) {
    this.name = StringUtils.prependIfMissing(name, "/");
  }

  public void validate() {
    enforceJsr303AnnotationValidations();
  }

  private void enforceJsr303AnnotationValidations() {
    final Set<ConstraintViolation<BaseCredentialRequest>> constraintViolations = Validation
      .buildDefaultValidatorFactory().getValidator().validate(this);
    for (final ConstraintViolation<BaseCredentialRequest> constraintViolation : constraintViolations) {
      throw new ParameterizedValidationException(constraintViolation.getMessage());
    }
  }

  abstract public GenerationParameters getGenerationParameters();
}
