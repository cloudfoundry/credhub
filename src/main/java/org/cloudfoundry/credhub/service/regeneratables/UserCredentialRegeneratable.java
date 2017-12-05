package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.request.UserGenerateRequest;

import java.util.List;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

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
