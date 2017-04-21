package io.pivotal.security.view;

import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.credential.RsaKey;

@SuppressWarnings("unused")
public class RsaView extends CredentialView {

  RsaView() {  /* Jackson */ }

  RsaView(RsaCredential rsaCredential) {
    super(
        rsaCredential.getVersionCreatedAt(),
        rsaCredential.getUuid(),
        rsaCredential.getName(),
        rsaCredential.getCredentialType(),
        new RsaKey(rsaCredential.getPublicKey(), rsaCredential.getPrivateKey())
    );
  }
}
