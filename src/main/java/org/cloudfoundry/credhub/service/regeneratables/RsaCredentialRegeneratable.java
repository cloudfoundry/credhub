package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.RsaGenerateRequest;

public class RsaCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(final CredentialVersion credentialVersion) {
    final RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credentialVersion;
    final RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaCredential.getName());
    generateRequest.setType(rsaCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
