package io.pivotal.security.view;

import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.secret.SshKey;

@SuppressWarnings("unused")
public class SshView extends SecretView {

  SshView() { /* Jackson */ }

  SshView(NamedSshSecret namedSshSecret) {
    super(
        namedSshSecret.getVersionCreatedAt(),
        namedSshSecret.getUuid(),
        namedSshSecret.getName(),
        namedSshSecret.getSecretType(),
        new SshKey(namedSshSecret.getPublicKey(), namedSshSecret.getPrivateKey(),
            namedSshSecret.getFingerprint())
    );
  }
}
