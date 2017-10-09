package io.pivotal.security.service.regeneratables;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.UserCredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

public class UserCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters) {
    UserCredentialVersion userCredential = (UserCredentialVersion) credentialVersion;
    UserGenerateRequest generateRequest = new UserGenerateRequest();

    generateRequest.setName(userCredential.getName());
    generateRequest.setType(userCredential.getCredentialType());

    generateRequest.setOverwrite(true);
    StringGenerationParameters generationParameters;
    generationParameters = userCredential.getGenerationParameters();

    if (generationParameters == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialVersion.getName()));
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_user");
    }

    generationParameters.setUsername(userCredential.getUsername());
    generateRequest.setGenerationParameters(generationParameters);

    return generateRequest;
  }
}
