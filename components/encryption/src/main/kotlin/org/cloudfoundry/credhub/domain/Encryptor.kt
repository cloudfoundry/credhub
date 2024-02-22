package org.cloudfoundry.credhub.domain

import org.cloudfoundry.credhub.entities.EncryptedValue
import java.util.UUID

interface Encryptor {
//    fun encrypt(clearTextValue: String?): EncryptedValue

    fun encrypt(clearTextValue: String?, credentialVersionUUID: UUID?): EncryptedValue

    fun decrypt(encryption: EncryptedValue?): String?
}
