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
public abstract class BaseSecretGenerateRequest extends BaseSecretPostRequest {
  private String type;
  private Boolean overwrite;

  public Boolean isOverwrite() {
    return overwrite;
  }

  public void setOverwrite(boolean overwrite) {
    this.overwrite = overwrite;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  @Override
  public void validate() {
    super.validate();

    if (!isValidSecretType(type)) {
      throw new ParameterizedValidationException("error.type_invalid");
    }

    if (!isValidTypeForGeneration(type)) {
      throw new ParameterizedValidationException("error.invalid_generate_type");
    }
  }

  private boolean isValidSecretType(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh", "value", "json").contains(type);
  }

  private boolean isValidTypeForGeneration(String type) {
    return newArrayList("password", "certificate", "rsa", "ssh").contains(type);
  }
}
