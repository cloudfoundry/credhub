package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion

class PasswordView : CredentialView {
    constructor() : super() {}
    constructor(passwordCredential: PasswordCredentialVersion) : super(
        passwordCredential.versionCreatedAt,
        passwordCredential.uuid,
        passwordCredential.name,
        passwordCredential.getCredentialType(),
        passwordCredential.metadata,
        StringCredentialValue(passwordCredential.password)
    ) {
    }
}
