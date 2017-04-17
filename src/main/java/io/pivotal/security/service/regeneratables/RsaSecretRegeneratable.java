package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;

public class RsaSecretRegeneratable implements Regeneratable {

  public RsaSecretRegeneratable() {
  }

  @Override
  public BaseSecretGenerateRequest createGenerateRequest(NamedSecret secret) {
    NamedRsaSecret rsaSecret = (NamedRsaSecret) secret;
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaSecret.getName());
    generateRequest.setType(rsaSecret.getSecretType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
