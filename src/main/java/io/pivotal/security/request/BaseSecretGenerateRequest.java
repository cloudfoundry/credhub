package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.pivotal.security.exceptions.ParameterizedValidationException;

import static com.google.common.collect.Lists.newArrayList;

@JsonTypeInfo(
  use         = JsonTypeInfo.Id.NAME,
  include     = JsonTypeInfo.As.PROPERTY,
  property    = "type",
  visible     = true,
  defaultImpl = DefaultSecretGenerateRequest.class  // TEMPORARY: Only needed while we're removing DocumentContext
)
@JsonSubTypes({
  @JsonSubTypes.Type(name = "password", value = PasswordGenerateRequest.class)
})
public abstract class BaseSecretGenerateRequest extends BaseSecretRequest {
  private boolean regenerate;

  @Override
  public void validate() {
    super.validate();

    if (!isValidTypeForGeneration(getType())) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }
  }

  private boolean isValidTypeForGeneration(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh").contains(type);
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }
}
