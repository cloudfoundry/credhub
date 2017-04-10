package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;

public class NotRegeneratable implements Regeneratable {

  @Override
  public BaseSecretGenerateRequest createGenerateRequest(NamedSecret secret) {
    throw new ParameterizedValidationException("error.invalid_type_with_regenerate_prompt");
  }
}
