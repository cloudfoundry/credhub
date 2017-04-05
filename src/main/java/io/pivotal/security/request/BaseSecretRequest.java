package io.pivotal.security.request;

import io.pivotal.security.exceptions.ParameterizedValidationException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.constraints.Pattern;
import java.util.Set;

public abstract class BaseSecretRequest {

  public static final String STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES
      = "^(?>(?:/?[^/]+))*$";

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES,
      message = "error.invalid_name_has_slash")
  private String name;
  private String type;
  private Boolean overwrite;
  private List<AccessControlEntry> accessControlEntries = new ArrayList<>();

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

  public List<AccessControlEntry> getAccessControlEntries() {
    return accessControlEntries;
  }

  public void setAccessControlEntries(List<AccessControlEntry> accessControlEntries) {
    this.accessControlEntries = accessControlEntries;
  }

  public void addCurrentUser(AccessControlEntry entry) {
    accessControlEntries = accessControlEntries
        .stream()
        .filter(ace -> !(ace.getActor().equals(entry.getActor())))
        .collect(Collectors.toList());
    accessControlEntries.add(entry);
  }

  public void validate() {
    enforceJsr303AnnotationValidations();
  }

  private void enforceJsr303AnnotationValidations() {
    final Set<ConstraintViolation<BaseSecretRequest>> constraintViolations = Validation
        .buildDefaultValidatorFactory().getValidator().validate(this);
    for (ConstraintViolation<BaseSecretRequest> constraintViolation : constraintViolations) {
      throw new ParameterizedValidationException(constraintViolation.getMessage());
    }
  }
}
