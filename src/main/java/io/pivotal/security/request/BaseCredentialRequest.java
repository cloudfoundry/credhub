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
  private static final String ONLY_VALID_CHARACTERS_IN_NAME = "^[a-zA-Z0-9-_/]*$";
  public static final String STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES
      = "^(?>(?:/?[^/]+))*$";

  @NotEmpty(message = "error.missing_name")
  @Pattern.List({
      @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES, message = "error.credential.invalid_slash_in_name"),
      @Pattern(regexp = ONLY_VALID_CHARACTERS_IN_NAME, message = "error.credential.invalid_character_in_name")
  })
  private String name;
  private String type;
  private boolean overwrite;
  private String mode;
  private List<PermissionEntry> additionalPermissions = new ArrayList<>();

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type.toLowerCase();
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public boolean shouldOverwrite() {
    return "overwrite".equals(mode) || overwrite;
  }

  public boolean isOverwrite() {
    return overwrite;
  }

  public void setOverwrite(boolean overwrite) {
    this.overwrite = overwrite;
  }

  public List<PermissionEntry> getAdditionalPermissions() {
    return additionalPermissions;
  }

  public void setAdditionalPermissions(List<PermissionEntry> additionalPermissions) {
    this.additionalPermissions = additionalPermissions;
  }

  public void addCurrentUser(PermissionEntry entry) {
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

  public String getMode() {
    return mode;
  }

  public void setMode(String mode) {
    this.mode = mode;
  }
}
