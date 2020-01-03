package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.domain.ValueCredentialVersion

class ValueView : CredentialView {
    constructor() : super() {}
    internal constructor(valueCredential: ValueCredentialVersion) : super(
        valueCredential.versionCreatedAt,
        valueCredential.uuid,
        valueCredential.name,
        valueCredential.getCredentialType(),
        StringCredentialValue((valueCredential.getValue() as String?)!!)
    ) {
    }
}
