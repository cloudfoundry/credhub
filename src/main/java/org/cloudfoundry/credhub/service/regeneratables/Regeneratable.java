package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;

import java.util.List;

public interface Regeneratable {

  BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters);
}
