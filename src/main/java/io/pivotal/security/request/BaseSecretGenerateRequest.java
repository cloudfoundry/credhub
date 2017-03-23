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
  private String type;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public void validate() {
    if (!isValidSecretType(type)) {
      throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
    }

    if (!isValidTypeForGeneration(type)) {
      throw new ParameterizedValidationException("error.cannot_generate_type");
    }
  }

  private boolean isValidSecretType(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh", "value", "json").contains(type);
  }

  private boolean isValidTypeForGeneration(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh").contains(type);
  }

  // These are only here because a set / generate request may have regenerate=false in it.
  private boolean regenerate;
  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }
}
