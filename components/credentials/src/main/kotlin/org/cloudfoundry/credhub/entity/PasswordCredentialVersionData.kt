package org.cloudfoundry.credhub.entity

import org.cloudfoundry.credhub.entities.EncryptedValue
import org.hibernate.annotations.NotFound
import org.hibernate.annotations.NotFoundAction
import javax.persistence.CascadeType
import javax.persistence.DiscriminatorValue
import javax.persistence.Entity
import javax.persistence.JoinColumn
import javax.persistence.OneToOne
import javax.persistence.PrimaryKeyJoinColumn
import javax.persistence.SecondaryTable

@Entity
@DiscriminatorValue(PasswordCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = PasswordCredentialVersionData.TABLE_NAME,
    pkJoinColumns = [PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")],
)
class PasswordCredentialVersionData : CredentialVersionData<PasswordCredentialVersionData> {
    @OneToOne(cascade = [CascadeType.ALL])
    @NotFound(action = NotFoundAction.IGNORE)
    @JoinColumn(table = TABLE_NAME, name = "password_parameters_uuid")
    var encryptedGenerationParameters: EncryptedValue? = null

    override val credentialType: String
        get() = CREDENTIAL_TYPE

    constructor() : super()

    constructor(name: String) : super(name)

    companion object {
        const val CREDENTIAL_TYPE = "password"
        const val TABLE_NAME = "password_credential"
    }
}
