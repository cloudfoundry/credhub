package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;

public class RsaCredentialRegeneratable implements Regeneratable {

  public RsaCredentialRegeneratable() {
  }

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(Credential credential) {
    RsaCredential rsaCredential = (RsaCredential) credential;
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaCredential.getName());
    generateRequest.setType(rsaCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
