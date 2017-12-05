package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;

@SuppressWarnings("unused")
public class RsaView extends CredentialView {

  RsaView() {  /* Jackson */ }

  RsaView(RsaCredentialVersion rsaCredential) {
    super(
        rsaCredential.getVersionCreatedAt(),
        rsaCredential.getUuid(),
        rsaCredential.getName(),
        rsaCredential.getCredentialType(),
        new RsaCredentialValue(rsaCredential.getPublicKey(), rsaCredential.getPrivateKey())
    );
  }
}
