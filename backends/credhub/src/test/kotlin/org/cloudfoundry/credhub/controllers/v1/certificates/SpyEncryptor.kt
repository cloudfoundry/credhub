package org.cloudfoundry.credhub.controllers.v1.certificates

import org.cloudfoundry.credhub.domain.Encryptor
import org.cloudfoundry.credhub.entities.EncryptedValue
import java.util.UUID

class SpyEncryptor : Encryptor {
    lateinit var encryptCalledwithString: String

    override fun encrypt(clearTextValue: String?): EncryptedValue {
        encryptCalledwithString = clearTextValue ?: "some-value"
        return EncryptedValue(UUID.randomUUID(), "some-value", "some-nonce")
    }

    override fun decrypt(encryption: EncryptedValue?): String? = encryptCalledwithString
}
