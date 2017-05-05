package io.pivotal.security.view;

import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.credential.SshCredentialValue;

@SuppressWarnings("unused")
public class SshView extends CredentialView {

  SshView() { /* Jackson */ }

  SshView(SshCredential sshCredential) {
    super(
        sshCredential.getVersionCreatedAt(),
        sshCredential.getUuid(),
        sshCredential.getName(),
        sshCredential.getCredentialType(),
        new SshCredentialValue(sshCredential.getPublicKey(), sshCredential.getPrivateKey(),
            sshCredential.getFingerprint())
    );
  }
}
