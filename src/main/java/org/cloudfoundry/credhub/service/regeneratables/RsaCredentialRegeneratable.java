package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.RsaGenerateRequest;

public class RsaCredentialRegeneratable implements Regeneratable {

  public RsaCredentialRegeneratable() {
  }

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion) {
    RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credentialVersion;
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaCredential.getName());
    generateRequest.setType(rsaCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
