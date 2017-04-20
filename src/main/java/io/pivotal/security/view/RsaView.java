package io.pivotal.security.view;

import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.credential.RsaKey;

@SuppressWarnings("unused")
public class RsaView extends CredentialView {

  RsaView() {  /* Jackson */ }

  RsaView(RsaCredential namedRsaSecret) {
    super(
        namedRsaSecret.getVersionCreatedAt(),
        namedRsaSecret.getUuid(),
        namedRsaSecret.getName(),
        namedRsaSecret.getSecretType(),
        new RsaKey(namedRsaSecret.getPublicKey(), namedRsaSecret.getPrivateKey())
    );
  }
}
