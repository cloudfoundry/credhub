package io.pivotal.security.request;

import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.constraints.Pattern;

public abstract class BaseCredentialRequest {

  public static final String STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES
      = "^(?>(?:/?[^/]+))*$";

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES,
      message = "error.invalid_name_has_slash")
  private String name;
  private String type;
  private boolean overwrite;
  private List<AccessControlEntry> additionalPermissions = new ArrayList<>();

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

  public boolean isOverwrite() {
    return overwrite;
  }

  public void setOverwrite(boolean overwrite) {
    this.overwrite = overwrite;
  }

  public List<AccessControlEntry> getAdditionalPermissions() {
    return additionalPermissions;
  }

  public void setAdditionalPermissions(List<AccessControlEntry> additionalPermissions) {
    this.additionalPermissions = additionalPermissions;
  }

  public void addCurrentUser(AccessControlEntry entry) {
    additionalPermissions = additionalPermissions
        .stream()
        .filter(ace -> !(ace.getActor().equals(entry.getActor())))
        .collect(Collectors.toList());
    additionalPermissions.add(entry);
  }

  public void validate() {
    enforceJsr303AnnotationValidations();
  }

  private void enforceJsr303AnnotationValidations() {
    final Set<ConstraintViolation<BaseCredentialRequest>> constraintViolations = Validation
        .buildDefaultValidatorFactory().getValidator().validate(this);
    for (ConstraintViolation<BaseCredentialRequest> constraintViolation : constraintViolations) {
      throw new ParameterizedValidationException(constraintViolation.getMessage());
    }
  }
}
