package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.request.BaseCredentialGenerateRequest;

public interface Regeneratable {

  BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion);
}
