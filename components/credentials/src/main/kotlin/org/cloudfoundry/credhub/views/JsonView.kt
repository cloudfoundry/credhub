package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.domain.JsonCredentialVersion

class JsonView : CredentialView {
    internal constructor() : super() /* Jackson */ {}
    internal constructor(jsonCredential: JsonCredentialVersion) : super(
        jsonCredential.versionCreatedAt,
        jsonCredential.uuid,
        jsonCredential.name,
        jsonCredential.getCredentialType(),
        JsonCredentialValue(jsonCredential.getValue()!!)
    ) {
    }
}
