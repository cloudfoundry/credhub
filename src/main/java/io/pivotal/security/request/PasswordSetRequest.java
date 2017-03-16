package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import org.hibernate.validator.constraints.NotEmpty;

public class PasswordSetRequest extends BaseSecretSetRequest {
  @NotEmpty(message = "error.missing_value")
  @JsonProperty("value")
  private String password;

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  @JsonIgnore
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    return NamedPasswordSecret.createNewVersion((NamedPasswordSecret) existing, name, this.getPassword(), encryptor, this.getAccessControlEntries());
  }
}
