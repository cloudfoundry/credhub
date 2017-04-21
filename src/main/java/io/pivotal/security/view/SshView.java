package io.pivotal.security.view;

import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.credential.SshKey;

@SuppressWarnings("unused")
public class SshView extends CredentialView {

  SshView() { /* Jackson */ }

  SshView(SshCredential sshCredential) {
    super(
        sshCredential.getVersionCreatedAt(),
        sshCredential.getUuid(),
        sshCredential.getName(),
        sshCredential.getCredentialType(),
        new SshKey(sshCredential.getPublicKey(), sshCredential.getPrivateKey(),
            sshCredential.getFingerprint())
    );
  }
}
