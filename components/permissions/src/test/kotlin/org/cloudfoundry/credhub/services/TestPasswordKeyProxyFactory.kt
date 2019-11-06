package org.cloudfoundry.credhub.services

import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata

@Service
@Profile("unit-test")
class TestPasswordKeyProxyFactory : PasswordKeyProxyFactory {
    override fun createPasswordKeyProxy(
        encryptionKeyMetadata: EncryptionKeyMetadata,
        encryptionService: InternalEncryptionService
    ): KeyProxy {
        return PasswordBasedKeyProxy(encryptionKeyMetadata.encryptionPassword, 1, encryptionService)
    }
}
