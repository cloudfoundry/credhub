package org.cloudfoundry.credhub.requests;

import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.exceptions.InvalidModeException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

import static com.google.common.collect.Lists.newArrayList;

@JsonTypeInfo(
  use = JsonTypeInfo.Id.CUSTOM,
  property = "type",
  visible = true,
  defaultImpl = DefaultCredentialGenerateRequest.class
)
@JsonTypeIdResolver(GenerateRequestTypeIdResolver.class)
@JsonSubTypes({
  @JsonSubTypes.Type(name = "password", value = PasswordGenerateRequest.class),
  @JsonSubTypes.Type(name = "ssh", value = SshGenerateRequest.class),
  @JsonSubTypes.Type(name = "rsa", value = RsaGenerateRequest.class),
  @JsonSubTypes.Type(name = "certificate", value = CertificateGenerateRequest.class),
  @JsonSubTypes.Type(name = "user", value = UserGenerateRequest.class),
})
public abstract class BaseCredentialGenerateRequest extends BaseCredentialRequest {
  private Boolean overwrite;
  private String rawOverwrite;
  private CredentialWriteMode mode;

  public boolean isOverwrite() {
    if (overwrite == null) {
      return false;
    }

    return overwrite;
  }

  public void setOverwrite(final Boolean overwrite) {
    this.overwrite = overwrite;
    rawOverwrite = String.valueOf(overwrite);
  }

  @Override
  public void validate() {
    super.validate();
    if (!isValidMode(this.getMode())) {
      throw new InvalidModeException(ErrorMessages.INVALID_MODE);
    }

    if (isInvalidCredentialType(getType())) {
      throw new ParameterizedValidationException(ErrorMessages.INVALID_TYPE_WITH_GENERATE_PROMPT);
    }

    if (isInvalidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException(ErrorMessages.CANNOT_GENERATE_TYPE);
    }

    if (this.getMode() != null && getRawOverwriteValue() != null) {
      throw new ParameterizedValidationException(ErrorMessages.OVERWRITE_AND_MODE_BOTH_PROVIDED);
    }

    if (getGenerationParameters() != null) {
      getGenerationParameters().validate();
    }

    if (getName() != null && getName().length() > 1024) {
      throw new ParameterizedValidationException(ErrorMessages.NAME_HAS_TOO_MANY_CHARACTERS);
    }
  }

  private String getRawOverwriteValue() {
    return rawOverwrite;
  }

  private boolean isValidMode(final CredentialWriteMode mode) {
    if (mode == null) {
      return true;
    }

    final List<CredentialWriteMode> modes = Arrays.asList(CredentialWriteMode.values());

    for (final CredentialWriteMode writeMode : modes) {
      if (writeMode.equals(mode)) {
        return true;
      }
    }

    return false;
  }

  private boolean isInvalidCredentialType(final String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "value", "json", "user").contains(type);
  }

  private boolean isInvalidTypeForGeneration(final String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "user").contains(type);
  }

  public CredentialWriteMode getMode() {
    return mode;
  }

  public void setMode(final CredentialWriteMode mode) {
    this.mode = mode;
  }
}
