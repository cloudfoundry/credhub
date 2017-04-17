package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PasswordGenerationParameters;

public class PasswordSecretRegeneratable implements Regeneratable {

  @Override
  public BaseSecretGenerateRequest createGenerateRequest(NamedSecret secret) {
    NamedPasswordSecret passwordSecret = (NamedPasswordSecret) secret;
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setName(passwordSecret.getName());
    generateRequest.setType(passwordSecret.getSecretType());
    PasswordGenerationParameters generationParameters;
    generationParameters = passwordSecret.getGenerationParameters();
    generateRequest.setOverwrite(true);

    if (generationParameters == null) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_password");
    }
    generateRequest.setGenerationParameters(generationParameters);
    return generateRequest;
  }
}
