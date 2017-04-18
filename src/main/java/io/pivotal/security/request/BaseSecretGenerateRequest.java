package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.GeneratorService;

import static com.google.common.collect.Lists.newArrayList;

@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = "type",
    visible = true,
    // TEMPORARY: Only needed while we're removing DocumentContext
    defaultImpl = DefaultSecretGenerateRequest.class
)
@JsonSubTypes({
    @JsonSubTypes.Type(name = "password", value = PasswordGenerateRequest.class),
    @JsonSubTypes.Type(name = "ssh", value = SshGenerateRequest.class),
    @JsonSubTypes.Type(name = "rsa", value = RsaGenerateRequest.class),
    @JsonSubTypes.Type(name = "certificate", value = CertificateGenerateRequest.class),
    @JsonSubTypes.Type(name = "user", value = UserGenerateRequest.class)
})
public abstract class BaseSecretGenerateRequest extends BaseSecretRequest {
  private boolean regenerate;

  @Override
  public void validate() {
    super.validate();

    if (isInvalidSecretType(getType())) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }

    if (isInvalidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException("error.cannot_generate_type");
    }
  }

  private boolean isInvalidSecretType(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "value", "json", "user").contains(type);
  }

  private boolean isInvalidTypeForGeneration(String type) {
    return !newArrayList("password", "certificate", "rsa", "ssh", "user").contains(type);
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }

  public abstract BaseSecretSetRequest generateSetRequest(GeneratorService generatorService);
}
