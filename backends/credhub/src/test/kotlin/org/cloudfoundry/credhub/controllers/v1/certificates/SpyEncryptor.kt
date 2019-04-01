package org.cloudfoundry.credhub.controllers.v1.certificates

import org.cloudfoundry.credhub.domain.Encryptor
import org.cloudfoundry.credhub.entities.EncryptedValue
import java.util.UUID

class SpyEncryptor : Encryptor {

    lateinit var encrypt__calledWith_string: String
    override fun encrypt(clearTextValue: String?): EncryptedValue {
        encrypt__calledWith_string = clearTextValue ?: "some-value"
        return EncryptedValue(UUID.randomUUID(), "some-value", "some-nonce")
    }

    override fun decrypt(encryption: EncryptedValue?): String? {
        return encrypt__calledWith_string
    }
}
