package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.credential.SshCredentialValue;

@SuppressWarnings("unused")
public class SshView extends CredentialView {

  SshView() { /* Jackson */ }

  SshView(SshCredentialVersion sshCredential) {
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
