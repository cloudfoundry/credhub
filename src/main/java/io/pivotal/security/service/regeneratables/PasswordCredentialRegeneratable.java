package io.pivotal.security.service.regeneratables;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.StringGenerationParameters;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

public class PasswordCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters) {
    PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) credentialVersion;
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setName(passwordCredential.getName());
    generateRequest.setType(passwordCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    StringGenerationParameters generationParameters;
    generationParameters = passwordCredential.getGenerationParameters();

    if (generationParameters == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialVersion.getName()));
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_password");
    }
    generateRequest.setGenerationParameters(generationParameters);
    return generateRequest;
  }
}
