package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;

public class RsaCredentialRegeneratable implements Regeneratable {

  public RsaCredentialRegeneratable() {
  }

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(Credential secret) {
    RsaCredential rsaSecret = (RsaCredential) secret;
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaSecret.getName());
    generateRequest.setType(rsaSecret.getSecretType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
