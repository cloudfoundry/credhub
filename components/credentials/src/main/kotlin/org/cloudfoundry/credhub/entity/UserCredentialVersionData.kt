package org.cloudfoundry.credhub.entity

import jakarta.persistence.CascadeType
import jakarta.persistence.Column
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
@DiscriminatorValue("user")
@SecondaryTable(
    name = UserCredentialVersionData.TABLE_NAME,
    pkJoinColumns = [PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")],
)
class UserCredentialVersionData
    @JvmOverloads
    constructor(
        name: String? = null,
    ) : CredentialVersionData<UserCredentialVersionData>(name) {
        @Column(table = UserCredentialVersionData.TABLE_NAME, length = 7000)
        var username: String? = null

        @Column(table = UserCredentialVersionData.TABLE_NAME, length = 20)
        var salt: String? = null

        @OneToOne(cascade = [CascadeType.ALL])
        @NotFound(action = NotFoundAction.IGNORE)
        @JoinColumn(table = UserCredentialVersionData.TABLE_NAME, name = "password_parameters_uuid")
        var encryptedGenerationParameters: EncryptedValue? = null

        override val credentialType: String
            get() = CREDENTIAL_TYPE

        companion object {
            const val TABLE_NAME = "user_credential"
            const val CREDENTIAL_TYPE = "user"
        }
    }
