package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.PasswordGenerateRequest;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;

public class PasswordCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(final CredentialVersion credentialVersion) {
    final PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) credentialVersion;
    final PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setName(passwordCredential.getName());
    generateRequest.setType(passwordCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    final StringGenerationParameters generationParameters;
    generationParameters = passwordCredential.getGenerationParameters();

    if (generationParameters == null) {
      throw new ParameterizedValidationException(
        "error.cannot_regenerate_non_generated_password");
    }
    generateRequest.setGenerationParameters(generationParameters);
    return generateRequest;
  }
}
