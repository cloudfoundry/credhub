package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.UserCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.request.StringGenerationParameters;

public class UserCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(Credential credential) {
    UserCredential userCredential = (UserCredential) credential;
    UserGenerateRequest generateRequest = new UserGenerateRequest();

    generateRequest.setName(userCredential.getName());
    generateRequest.setType(userCredential.getCredentialType());

    generateRequest.setOverwrite(true);
    StringGenerationParameters generationParameters;
    generationParameters = userCredential.getGenerationParameters();

    if (generationParameters == null) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_user");
    }

    generationParameters.setUsername(userCredential.getUsername());
    generateRequest.setGenerationParameters(generationParameters);

    return generateRequest;
  }
}
