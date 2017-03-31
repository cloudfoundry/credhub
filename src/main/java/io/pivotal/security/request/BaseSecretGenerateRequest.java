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
    @JsonSubTypes.Type(name = "password", value = PasswordGenerateRequest.class)
})
public abstract class BaseSecretGenerateRequest extends BaseSecretRequest {

  private boolean regenerate;

  @Override
  public void validate() {
    super.validate();

    if (!isValidSecretType(getType())) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }

    if (!isValidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException("error.cannot_generate_type");
    }
  }

  private boolean isValidSecretType(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh", "value", "json").contains(type);
  }

  private boolean isValidTypeForGeneration(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh").contains(type);
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }

  public abstract BaseSecretSetRequest generateSetRequest(GeneratorService generatorService);
}
