package org.cloudfoundry.credhub.entity

import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity

@Entity
@DiscriminatorValue(ValueCredentialVersionData.CREDENTIAL_TYPE)
class ValueCredentialVersionData : CredentialVersionData<ValueCredentialVersionData> {
    override val credentialType: String
        get() = CREDENTIAL_TYPE

    constructor() : super()

    constructor(name: String) : super(name)

    companion object {
        const val CREDENTIAL_TYPE = "value"
    }
}
