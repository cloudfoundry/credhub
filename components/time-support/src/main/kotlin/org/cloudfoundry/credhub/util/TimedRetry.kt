package org.cloudfoundry.credhub.util

import java.util.function.Supplier

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
class TimedRetry @Autowired
constructor(private val currentTimeProvider: CurrentTimeProvider) {

    fun retryEverySecondUntil(durationInSeconds: Long, untilTrue: Supplier<Boolean>): Boolean {
        val startTime = currentTimeProvider.currentTimeMillis()
        var currentTime: Long
        val endTime = startTime + ONE_SECOND * durationInSeconds

        do {
            if (untilTrue.get()) {
                return true
            }
            try {
                currentTimeProvider.sleep(ONE_SECOND.toLong())
            } catch (e: InterruptedException) {
                // do nothing until we want to use InterruptedExceptions to
                // cause graceful shutdowns
            }

            currentTime = currentTimeProvider.currentTimeMillis()
        } while (currentTime < endTime)

        return false
    }

    companion object {

        val ONE_SECOND = 1000
    }
}
