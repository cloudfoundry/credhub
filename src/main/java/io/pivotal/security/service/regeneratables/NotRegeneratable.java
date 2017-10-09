package io.pivotal.security.service.regeneratables;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;

import java.util.List;

public class NotRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters) {
    throw new ParameterizedValidationException("error.invalid_type_with_regenerate_prompt");
  }
}
