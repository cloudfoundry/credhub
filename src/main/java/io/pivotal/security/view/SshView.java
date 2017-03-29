package io.pivotal.security.view;

import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.secret.SshKey;
import java.security.NoSuchAlgorithmException;

class SshView extends SecretView {

  SshView(NamedSshSecret namedSshSecret) throws NoSuchAlgorithmException {
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
