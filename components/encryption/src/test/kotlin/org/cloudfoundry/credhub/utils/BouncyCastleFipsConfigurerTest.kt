package org.cloudfoundry.credhub.utils

import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.cloudfoundry.credhub.config.BouncyCastleProviderConfiguration
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@ContextConfiguration(classes = [BouncyCastleProviderConfiguration::class])
internal class BouncyCastleFipsConfigurerTest {
    companion object {
        @BeforeClass
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
