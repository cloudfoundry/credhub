package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Service
@Profile("unit-test")
class TestPasswordKeyProxyFactory : PasswordKeyProxyFactory {
    override fun createPasswordKeyProxy(
        encryptionKeyMetadata: EncryptionKeyMetadata,
        encryptionService: InternalEncryptionService,
    ): KeyProxy {
        return PasswordBasedKeyProxy(encryptionKeyMetadata.encryptionPassword, 1, encryptionService)
    }
}
