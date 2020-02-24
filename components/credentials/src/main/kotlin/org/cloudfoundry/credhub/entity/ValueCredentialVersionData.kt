package org.cloudfoundry.credhub.entity

import javax.persistence.DiscriminatorValue
import javax.persistence.Entity

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
