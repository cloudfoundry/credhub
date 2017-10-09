package io.pivotal.security.service.regeneratables;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.RsaCredentialVersion;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;

import java.util.List;

public class RsaCredentialRegeneratable implements Regeneratable {

  public RsaCredentialRegeneratable() {
  }

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters) {
    RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credentialVersion;
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaCredential.getName());
    generateRequest.setType(rsaCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
