package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;

public class NotRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(final CredentialVersion credentialVersion) {
    throw new ParameterizedValidationException(ErrorMessages.INVALID_TYPE_WITH_REGENERATE_PROMPT);
  }
}
