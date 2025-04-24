package org.cloudfoundry.credhub.entity

import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.SecondaryTable

@Entity
@DiscriminatorValue(SshCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = SshCredentialVersionData.TABLE_NAME,
    pkJoinColumns = [PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")],
)
class SshCredentialVersionData
    @JvmOverloads
    constructor(
        name: String? = null,
    ) : CredentialVersionData<SshCredentialVersionData>(name) {
        @Column(table = SshCredentialVersionData.TABLE_NAME, length = 7000)
        var publicKey: String? = null

        override val credentialType: String
            get() = CREDENTIAL_TYPE

        companion object {
            const val CREDENTIAL_TYPE = "ssh"
            const val TABLE_NAME = "ssh_credential"
        }
    }
