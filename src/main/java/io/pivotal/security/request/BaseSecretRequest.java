package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.Pattern;

public abstract class BaseSecretRequest {
  public static final String STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES = "^(?>(?:/?[^/]+))*$";

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES, message = "error.invalid_name_has_slash")
  private String name;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  private Boolean overwrite;

  public Boolean isOverwrite() {
    return overwrite != null && overwrite;
  }

  public void setOverwrite(Boolean overwrite) {
    this.overwrite = overwrite;
  }

  @JsonIgnore
  abstract public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor);
}
