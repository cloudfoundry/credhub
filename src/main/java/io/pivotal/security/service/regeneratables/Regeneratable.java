package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.Credential;
import io.pivotal.security.request.BaseCredentialGenerateRequest;

public interface Regeneratable {

  BaseCredentialGenerateRequest createGenerateRequest(Credential secret);
}
