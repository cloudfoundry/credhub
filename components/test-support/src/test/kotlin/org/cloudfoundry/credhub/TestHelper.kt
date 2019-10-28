package org.cloudfoundry.credhub

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.mockito.Mockito.`when`
import java.security.Security
import java.time.Instant
import java.time.temporal.TemporalAccessor
import java.util.Optional
import java.util.function.Consumer

class TestHelper private constructor(){
    companion object {

        @JvmStatic
        fun mockOutCurrentTimeProvider(mockCurrentTimeProvider: CurrentTimeProvider): Consumer<Long> {
            return Consumer<Long> { epochMillis ->
                `when`<Optional<TemporalAccessor>>(mockCurrentTimeProvider.now).thenReturn(Optional.of(Instant.ofEpochMilli(epochMillis)))
                `when`<Instant>(mockCurrentTimeProvider.instant).thenReturn(Instant.ofEpochMilli(epochMillis))
            }
        }

        @JvmStatic
        fun getBouncyCastleFipsProvider(): BouncyCastleFipsProvider {
            var bouncyCastleFipsProvider: BouncyCastleFipsProvider? = Security
                .getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) as BouncyCastleFipsProvider

            if (bouncyCastleFipsProvider == null) {
                bouncyCastleFipsProvider = BouncyCastleFipsProvider()
                Security.addProvider(bouncyCastleFipsProvider)
            }

            return bouncyCastleFipsProvider
        }
    }
}