package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.domain.SshCredentialVersion

class SshView : CredentialView {
    internal constructor() : super() /* Jackson */ {}
    internal constructor(sshCredential: SshCredentialVersion) : super(
        sshCredential.versionCreatedAt,
        sshCredential.uuid,
        sshCredential.name,
        sshCredential.getCredentialType(),
        SshCredentialValue(sshCredential.publicKey, sshCredential.privateKey,
            sshCredential.fingerprint)
    ) {
    }
}
