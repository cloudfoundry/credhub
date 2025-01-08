package org.cloudfoundry.credhub.entity

import org.cloudfoundry.credhub.utils.RsaCredentialHelper
import javax.persistence.Column
import javax.persistence.DiscriminatorValue
import javax.persistence.Entity
import javax.persistence.PrimaryKeyJoinColumn
import javax.persistence.SecondaryTable

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
