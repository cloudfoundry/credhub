package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.domain.RsaCredentialVersion

class RsaView : CredentialView {
    internal constructor() : super() /* Jackson */ {}
    internal constructor(rsaCredential: RsaCredentialVersion) : super(
        rsaCredential.versionCreatedAt,
        rsaCredential.uuid,
        rsaCredential.name,
        rsaCredential.getCredentialType(),
        rsaCredential.metadata,
        RsaCredentialValue(rsaCredential.publicKey, rsaCredential.privateKey)
    ) {
    }
}
