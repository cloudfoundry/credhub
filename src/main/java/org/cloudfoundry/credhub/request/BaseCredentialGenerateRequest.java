package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.exceptions.InvalidModeException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

import java.util.Arrays;
import java.util.List;

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
    @JsonSubTypes.Type(name = "user", value = UserGenerateRequest.class)
})
public abstract class BaseCredentialGenerateRequest extends BaseCredentialRequest {
  private Boolean overwrite;
  private String rawOverwrite;
  private CredentialWriteMode mode;

  public boolean isOverwrite() {
    return overwrite == null ? false : overwrite;
  }

  public void setOverwrite(Boolean overwrite) {
    this.overwrite = overwrite;
    rawOverwrite = String.valueOf(overwrite);
  }

  @Override
  public abstract GenerationParameters getGenerationParameters();

  @Override
  public void validate() {
    super.validate();
    if (getGenerationParameters() != null && !isValidMode(getGenerationParameters().getMode())) {
      throw new InvalidModeException("error.invalid_mode");
    }

    if (isInvalidCredentialType(getType())) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }

    if (isInvalidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException("error.cannot_generate_type");
    }

    if (getGenerationParameters() != null &&
        getGenerationParameters().getMode() != null && getRawOverwriteValue() != null) {
      throw new ParameterizedValidationException("error.overwrite_and_mode_both_provided");
    }

    if (getGenerationParameters() != null) {
      getGenerationParameters().validate();
    }

    if (getName() != null && getName().length() > 1024) {
      throw new ParameterizedValidationException("error.name_has_too_many_characters");
    }
  }

  private String getRawOverwriteValue() {
    return rawOverwrite;
  }

  private boolean isValidMode(CredentialWriteMode mode){
    if(mode == null){
      return true;
    }

    List<CredentialWriteMode> modes = Arrays.asList(CredentialWriteMode.values());

    for(CredentialWriteMode writeMode : modes){
      if(writeMode.equals(mode)){
        return true;
      }
    }

    return false;
  }

  private boolean isInvalidCredentialType(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "value", "json", "user").contains(type);
  }

  private boolean isInvalidTypeForGeneration(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "user").contains(type);
  }
}
