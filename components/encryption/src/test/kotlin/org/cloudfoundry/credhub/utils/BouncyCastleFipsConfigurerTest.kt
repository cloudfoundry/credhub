package org.cloudfoundry.credhub.utils

import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.cloudfoundry.credhub.config.BouncyCastleProviderConfiguration
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [BouncyCastleProviderConfiguration::class])
internal class BouncyCastleFipsConfigurerTest {
    companion object {
        @BeforeAll
        @JvmStatic
        fun setUp() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @Test
    fun defaultConfiguredToFipsApprovedSecureRandom() {
        assertTrue(CryptoServicesRegistrar.isInApprovedOnlyMode())
    }
}
