package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;

import javax.validation.Valid;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest{

  @Valid
  @JsonProperty("value")
  private PasswordGenerationParameters generationParams;

  public PasswordGenerationParameters getGenerationParams() {
    return generationParams;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    return null;
  }
}
