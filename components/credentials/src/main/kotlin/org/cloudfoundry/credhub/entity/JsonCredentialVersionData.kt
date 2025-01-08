package org.cloudfoundry.credhub.entity

import javax.persistence.DiscriminatorValue
import javax.persistence.Entity

@Entity
@DiscriminatorValue(JsonCredentialVersionData.CREDENTIAL_TYPE)
class JsonCredentialVersionData : CredentialVersionData<JsonCredentialVersionData> {
    override val credentialType: String
        get() = CREDENTIAL_TYPE

    constructor() : super() {}

    constructor(name: String) : super(name) {}

    companion object {
        const val CREDENTIAL_TYPE = "json"
    }
}
