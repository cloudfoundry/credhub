package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
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
  @Override
  public abstract GenerationParameters getGenerationParameters();

  @Override
  public void validate() {
    super.validate();

    if (isInvalidCredentialType(getType())) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }

    if (isInvalidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException("error.cannot_generate_type");
    }

    if (getMode() != null && getRawOverwriteValue() != null) {
      throw new ParameterizedValidationException("error.overwrite_and_mode_both_provided");
    }

    if (getGenerationParameters() != null) {
      getGenerationParameters().validate();
    }
  }

  private boolean isInvalidCredentialType(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "value", "json", "user").contains(type);
  }

  private boolean isInvalidTypeForGeneration(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "user").contains(type);
  }
}
