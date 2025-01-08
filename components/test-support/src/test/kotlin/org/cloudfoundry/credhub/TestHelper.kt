package org.cloudfoundry.credhub

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.mockito.Mockito.`when`
import java.security.Security
import java.time.Instant
import java.time.temporal.TemporalAccessor
import java.util.Optional
import java.util.function.Consumer

class TestHelper private constructor() {
    companion object {
        @JvmStatic
        fun mockOutCurrentTimeProvider(mockCurrentTimeProvider: CurrentTimeProvider): Consumer<Long> =
            Consumer<Long> { epochMillis ->
                `when`<Optional<TemporalAccessor>>(mockCurrentTimeProvider.now).thenReturn(Optional.of(Instant.ofEpochMilli(epochMillis)))
                `when`<Instant>(mockCurrentTimeProvider.instant).thenReturn(Instant.ofEpochMilli(epochMillis))
            }

        @JvmStatic
        fun getBouncyCastleFipsProvider(): BouncyCastleFipsProvider =
            Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) as? BouncyCastleFipsProvider
                ?: BouncyCastleFipsProvider().apply { Security.addProvider(this) }
    }
}
