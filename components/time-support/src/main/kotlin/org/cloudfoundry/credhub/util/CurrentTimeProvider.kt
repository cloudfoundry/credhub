package org.cloudfoundry.credhub.util

import org.springframework.data.auditing.DateTimeProvider
import org.springframework.stereotype.Component
import java.time.Instant
import java.time.temporal.TemporalAccessor
import java.util.Optional

@Component
open class CurrentTimeProvider : DateTimeProvider {
    open val instant: Instant
        get() = Instant.now()

    override fun getNow(): Optional<TemporalAccessor> = Optional.of(instant)

    open fun currentTimeMillis(): Long = System.currentTimeMillis()

    @Throws(InterruptedException::class)
    open fun sleep(sleepTimeInMillis: Long) {
        Thread.sleep(sleepTimeInMillis)
    }
}
