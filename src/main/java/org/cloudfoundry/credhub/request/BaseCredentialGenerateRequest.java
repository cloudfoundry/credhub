package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
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
    @JsonSubTypes.Type(name = "user", value = UserGenerateRequest.class)
})
public abstract class BaseCredentialGenerateRequest extends BaseCredentialRequest {
  private Boolean overwrite;
  private String mode;

  public boolean isOverwrite() {
    return overwrite == null ? false : overwrite;
  }

  public void setOverwrite(Boolean overwrite) {
    this.overwrite = overwrite;
  }

  @Override
  public abstract GenerationParameters getGenerationParameters();

  @Override
  public void validate() {
    super.validate();

    if (getGenerationParameters() != null && isInvalidMode(getGenerationParameters().getMode())) {
      throw new InvalidModeException("error.invalid_mode");
    }

    if (isInvalidCredentialType(getType())) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }

    if (isInvalidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException("error.cannot_generate_type");
    }

    if (getGenerationParameters() != null) {
      getGenerationParameters().validate();
    }

    if (getName() != null && getName().length() > 1024) {
      throw new ParameterizedValidationException("error.name_has_too_many_characters");
    }
  }

  private boolean isInvalidMode(String mode){
    return mode != null && !mode.equals("converge");
  }

  private boolean isInvalidCredentialType(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "value", "json", "user").contains(type);
  }

  private boolean isInvalidTypeForGeneration(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "user").contains(type);
  }
}
