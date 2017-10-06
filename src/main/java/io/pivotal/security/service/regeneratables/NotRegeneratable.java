package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;

public class NotRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion) {
    throw new ParameterizedValidationException("error.invalid_type_with_regenerate_prompt");
  }
}
