package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest{

  @JsonProperty("parameters")
  private PasswordGenerationParameters generationParameters;

  public PasswordGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    return null;
  }
}
