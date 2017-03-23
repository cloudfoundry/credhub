package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.constraints.Pattern;
import java.util.Set;

public abstract class BaseSecretRequest {
  public static final String STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES = "^(?>(?:/?[^/]+))*$";

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES, message = "error.invalid_name_has_slash")
  private String name;
  private String type;
  private Boolean overwrite;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Boolean isOverwrite() {
    return overwrite != null && overwrite;
  }

  public void setOverwrite(Boolean overwrite) {
    this.overwrite = overwrite;
  }

  @JsonIgnore
  abstract public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor);

  public void validate() {
    enforceJSR303AnnotationValidations();
  }

  private void enforceJSR303AnnotationValidations() {
    final Set<ConstraintViolation<BaseSecretRequest>> constraintViolations = Validation.buildDefaultValidatorFactory().getValidator().validate(this);
    for (ConstraintViolation<BaseSecretRequest> constraintViolation : constraintViolations) {
      throw new ParameterizedValidationException(constraintViolation.getMessage());
    }
  }
}
