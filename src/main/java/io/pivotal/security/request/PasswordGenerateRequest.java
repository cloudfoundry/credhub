package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.SecretGenerator;

import java.util.List;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest {
  public static final List<AccessControlEntry> NULL_ACCESS_CONTROL_ENTRIES = null;
  @JsonProperty("parameters")
  private PasswordGenerationParameters generationParameters;

  public PasswordGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new PasswordGenerationParameters();
    }
    return generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor, SecretGenerator secretGenerator) {
    String newPassword = ((PassayStringSecretGenerator)secretGenerator).generateSecret(getGenerationParameters()).getPassword();
    return NamedPasswordSecret.createNewVersion((NamedPasswordSecret) existing, getName(), newPassword, getGenerationParameters(), encryptor, NULL_ACCESS_CONTROL_ENTRIES);
  }
}
