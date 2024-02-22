package org.cloudfoundry.credhub.domain

import org.cloudfoundry.credhub.entities.EncryptedValue

interface Encryptor {
    fun encrypt(clearTextValue: String?): EncryptedValue

    fun decrypt(encryption: EncryptedValue?): String?
}
