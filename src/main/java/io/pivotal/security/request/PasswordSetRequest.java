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
  @JsonIgnore
  private PasswordGenerationParameters generationParameters;

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public void setGenerationParameters(PasswordGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  @JsonIgnore
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    return NamedPasswordSecret.createNewVersion(
            (NamedPasswordSecret) existing,
            getName(),
            getPassword(),
            generationParameters,
            encryptor,
            getAccessControlEntries()
    );
  }
}
