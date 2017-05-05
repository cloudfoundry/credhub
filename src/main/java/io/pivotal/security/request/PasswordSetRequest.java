package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class PasswordSetRequest extends BaseCredentialSetRequest<PasswordCredential> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private StringCredential password;

  @JsonIgnore
  private StringGenerationParameters generationParameters;

  public StringCredential getPassword() {
    return password;
  }

  public void setPassword(StringCredential password) {
    this.password = password;
  }

  public void setGenerationParameters(StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  public StringGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  @Override
  @JsonIgnore
  public PasswordCredential createNewVersion(PasswordCredential existing, Encryptor encryptor) {
    return PasswordCredential.createNewVersion(
        existing,
        getName(),
        getPassword().getStringCredential(),
        getGenerationParameters(),
        encryptor
    );
  }
}
