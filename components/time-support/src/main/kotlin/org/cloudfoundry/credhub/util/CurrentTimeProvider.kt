package org.cloudfoundry.credhub.util

import java.time.Instant
import java.time.temporal.TemporalAccessor
import java.util.Optional

import org.springframework.data.auditing.DateTimeProvider
import org.springframework.stereotype.Component

@Component
open class CurrentTimeProvider : DateTimeProvider {

    open val instant: Instant
        get() = Instant.now()

    override fun getNow(): Optional<TemporalAccessor> {
        return Optional.of(instant)
    }

    open fun currentTimeMillis(): Long {
        return System.currentTimeMillis()
    }

    @Throws(InterruptedException::class)
    open fun sleep(sleepTimeInMillis: Long) {
        Thread.sleep(sleepTimeInMillis)
    }
}
