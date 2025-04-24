package org.cloudfoundry.credhub.entity

import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.SecondaryTable
import org.cloudfoundry.credhub.utils.RsaCredentialHelper

@Entity
@DiscriminatorValue(RsaCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = RsaCredentialVersionData.TABLE_NAME,
    pkJoinColumns = [PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")],
)
class RsaCredentialVersionData
    @JvmOverloads
    constructor(
        name: String? = null,
    ) : CredentialVersionData<RsaCredentialVersionData>(name) {
        @Column(table = RsaCredentialVersionData.TABLE_NAME, length = 7000)
        var publicKey: String? = null

        override val credentialType: String
            get() = CREDENTIAL_TYPE

        val keyLength: Int
            get() {
                val rsaCredentialHelper = RsaCredentialHelper(this)
                return rsaCredentialHelper.keyLength
            }

        companion object {
            const val CREDENTIAL_TYPE = "rsa"
            const val TABLE_NAME = "rsa_credential"
        }
    }
