package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;

public interface Regeneratable {

  BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion);
}
