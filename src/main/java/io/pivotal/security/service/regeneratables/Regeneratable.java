package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.request.BaseSecretGenerateRequest;

public interface Regeneratable {

  BaseSecretGenerateRequest createGenerateRequest(NamedSecret secret);
}
