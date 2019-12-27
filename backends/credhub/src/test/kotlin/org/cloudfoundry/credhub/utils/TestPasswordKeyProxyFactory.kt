package org.cloudfoundry.credhub.utils

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata
import org.cloudfoundry.credhub.services.InternalEncryptionService
import org.cloudfoundry.credhub.services.KeyProxy
import org.cloudfoundry.credhub.services.PasswordBasedKeyProxy
import org.cloudfoundry.credhub.services.PasswordKeyProxyFactory
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

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
