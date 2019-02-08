package org.cloudfoundry.credhub.views;

import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;

@SuppressWarnings("unused")
public class SshView extends CredentialView {

  SshView() {
    super(); /* Jackson */
  }

  SshView(final SshCredentialVersion sshCredential) {
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
