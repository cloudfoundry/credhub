package org.cloudfoundry.credhub.util;

import org.cloudfoundry.credhub.helper.FakeCurrentTimeProvider;
import org.junit.Before;
import org.junit.Test;

import java.util.function.Supplier;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class TimedRetryTest {

  private FakeCurrentTimeProvider currentTimeProvider;
  private TimedRetry subject;
  private int retryCount;
  private long expectedTime;
  private long startTime;
  private long durationInSeconds;
  private long endTime;

  @Before
  public void setup() throws Exception {
    currentTimeProvider = new FakeCurrentTimeProvider();

    startTime = 1490000000L;
    durationInSeconds = 10000;
    endTime = startTime + 1000 * durationInSeconds;
    currentTimeProvider.setCurrentTimeMillis(startTime);

    subject = new TimedRetry(currentTimeProvider);
  }

  @Test
  public void retryEverySecondUntil_alwaysTriesAtLeastOnce() throws Exception {
    subject.retryEverySecondUntil(0L, () -> incrementCountToTen());

    assertThat(retryCount, equalTo(1));
  }

  @Test
  public void retryEverySecondUntil_triesEverySecond() throws Exception {
    expectedTime = startTime;
    // this should get called twice, once right away and once again after one second has passed
    // it asserts that and allows the TimedRetry to stop after the second assertion
    Supplier<Boolean> checkTime = () -> {
      assertThat(expectedTime, equalTo(currentTimeProvider.currentTimeMillis()));
      if (expectedTime < endTime) {
        expectedTime += 1000;
        return false;
      }
      return true;
    };

    subject.retryEverySecondUntil(durationInSeconds, checkTime);

    assertThat(currentTimeProvider.currentTimeMillis(), equalTo(endTime));
  }

  @Test
  public void retryEverySecondUntil_returnsFalseOnTimeout() {
    assertThat(subject.retryEverySecondUntil(durationInSeconds, () -> false), equalTo(false));
    assertThat(currentTimeProvider.currentTimeMillis(), equalTo(endTime));
  }
  
  private boolean incrementCountToTen() {
    if (retryCount < 10) {
      retryCount++;
      return true;
    }
    return false;
  }
}
