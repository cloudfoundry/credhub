package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.Credential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;

public class NotRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(Credential credential) {
    throw new ParameterizedValidationException("error.invalid_type_with_regenerate_prompt");
  }
}
