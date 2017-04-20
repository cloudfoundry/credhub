package io.pivotal.security.view;

import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.credential.SshKey;

@SuppressWarnings("unused")
public class SshView extends CredentialView {

  SshView() { /* Jackson */ }

  SshView(SshCredential namedSshSecret) {
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
