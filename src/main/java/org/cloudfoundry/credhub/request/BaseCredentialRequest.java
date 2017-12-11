package org.cloudfoundry.credhub.request;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
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
  public static final String HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH
      = "^(/|(?>(?:/?[^/]+))*)$";
  private static final String IS_NOT_EMPTY = "^(.|\n){2,}$";

  @NotEmpty(message = "error.missing_name")
  @Pattern.List({
      @Pattern(regexp = HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH, message = "error.credential.invalid_slash_in_name"),
      @Pattern(regexp = ONLY_VALID_CHARACTERS_IN_NAME, message = "error.credential.invalid_character_in_name"),
      @Pattern(regexp = IS_NOT_EMPTY, message = "error.missing_name")
  })
  private String name;
  private String type;
  private Boolean overwrite;
  private CredentialWriteMode mode;
  private List<PermissionEntry> additionalPermissions = new ArrayList<>();
  private GenerationParameters generationParameters = null;

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
    this.name = StringUtils.prependIfMissing(name, "/");
  }

  public String getOverwriteMode() {
    if (mode != null) {
      return mode.mode;
    }
    if (isOverwrite()) {
      return CredentialWriteMode.OVERWRITE.mode;
    }
    return CredentialWriteMode.NO_OVERWRITE.mode;
  }

  public boolean isOverwrite() {
    return overwrite == null ? false : overwrite;
  }

  public Boolean getRawOverwriteValue() {
    return overwrite;
  }

  public void setOverwrite(Boolean overwrite) {
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

  public CredentialWriteMode getMode() {
    return mode;
  }

  public void setMode(CredentialWriteMode mode) {
    this.mode = mode;
  }

  public GenerationParameters getGenerationParameters() {
    return generationParameters;
  }

}
