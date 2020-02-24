package org.cloudfoundry.credhub.entity

import javax.persistence.Column
import javax.persistence.DiscriminatorValue
import javax.persistence.Entity
import javax.persistence.PrimaryKeyJoinColumn
import javax.persistence.SecondaryTable

@Entity
@DiscriminatorValue(SshCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(name = SshCredentialVersionData.TABLE_NAME, pkJoinColumns = [PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")])
class SshCredentialVersionData @JvmOverloads constructor(name: String? = null) : CredentialVersionData<SshCredentialVersionData>(name) {

    @Column(table = SshCredentialVersionData.TABLE_NAME, length = 7000)
    var publicKey: String? = null

    override val credentialType: String
        get() = CREDENTIAL_TYPE

    companion object {
        const val CREDENTIAL_TYPE = "ssh"
        const val TABLE_NAME = "ssh_credential"
    }
}
