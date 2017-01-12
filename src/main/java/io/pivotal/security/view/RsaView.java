package io.pivotal.security.view;

import io.pivotal.security.entity.NamedRsaSecret;

public class RsaView extends SecretView {
  RsaView(NamedRsaSecret namedRsaSecret) {
    super(
        namedRsaSecret.getVersionCreatedAt(),
        namedRsaSecret.getUuid(),
        namedRsaSecret.getName(),
        namedRsaSecret.getSecretType(),
        new RsaBody(namedRsaSecret.getPublicKey(), namedRsaSecret.getPrivateKey())
    );
  }
}
