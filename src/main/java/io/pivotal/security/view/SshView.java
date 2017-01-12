package io.pivotal.security.view;

import io.pivotal.security.entity.NamedSshSecret;

class SshView extends SecretView {
  SshView(NamedSshSecret namedSshSecret) {
    super(
        namedSshSecret.getVersionCreatedAt(),
        namedSshSecret.getUuid(),
        namedSshSecret.getName(),
        namedSshSecret.getSecretType(),
        new SshBody(namedSshSecret.getPublicKey(), namedSshSecret.getPrivateKey())
    );
  }
}
