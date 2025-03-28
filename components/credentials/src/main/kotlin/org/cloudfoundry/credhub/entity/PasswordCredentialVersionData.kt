package org.cloudfoundry.credhub.entity

import jakarta.persistence.CascadeType
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.JoinColumn
import jakarta.persistence.OneToOne
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.SecondaryTable
import org.cloudfoundry.credhub.entities.EncryptedValue
import org.hibernate.annotations.NotFound
import org.hibernate.annotations.NotFoundAction

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
