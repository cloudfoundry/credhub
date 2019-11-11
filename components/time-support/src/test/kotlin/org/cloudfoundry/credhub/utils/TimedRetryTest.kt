package org.cloudfoundry.credhub.utils

import java.util.function.Supplier

import org.cloudfoundry.credhub.util.TimedRetry
import org.junit.Before
import org.junit.Test

import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat

class TimedRetryTest {

    private var currentTimeProvider: FakeCurrentTimeProvider? = null
    private var subject: TimedRetry? = null
    private var retryCount: Int = 0
    private var expectedTime: Long = 0
    private var startTime: Long = 0
    private var durationInSeconds: Long = 0
    private var endTime: Long = 0

    @Before
    @Throws(Exception::class)
    fun setup() {
        currentTimeProvider = FakeCurrentTimeProvider()

        startTime = 1490000000L
        durationInSeconds = 10000
        endTime = startTime + 1000 * durationInSeconds
        currentTimeProvider!!.setCurrentTimeMillis(startTime)

        subject = TimedRetry(currentTimeProvider)
    }

    @Test
    @Throws(Exception::class)
    fun retryEverySecondUntil_alwaysTriesAtLeastOnce() {
        subject!!.retryEverySecondUntil(0L) { incrementCountToTen() }

        assertThat(retryCount, equalTo(1))
    }

    @Test
    @Throws(Exception::class)
    fun retryEverySecondUntil_triesEverySecond() {
        expectedTime = startTime
        // this should get called twice, once right away and once again after one second has passed
        // it asserts that and allows the TimedRetry to stop after the second assertion
        val checkTime = {
            assertThat(expectedTime, equalTo(currentTimeProvider!!.currentTimeMillis()))
            if (expectedTime < endTime) {
                expectedTime += 1000
                false
            } else {
                true
            }
        }

        subject!!.retryEverySecondUntil(durationInSeconds, checkTime)

        assertThat(currentTimeProvider!!.currentTimeMillis(), equalTo(endTime))
    }

    @Test
    fun retryEverySecondUntil_returnsFalseOnTimeout() {
        assertThat(subject!!.retryEverySecondUntil(durationInSeconds) { false }, equalTo(false))
        assertThat(currentTimeProvider!!.currentTimeMillis(), equalTo(endTime))
    }

    private fun incrementCountToTen(): Boolean {
        if (retryCount < 10) {
            retryCount++
            return true
        }
        return false
    }
}
