package org.cloudfoundry.credhub.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@Component
public class TimedRetry {

  public static final int ONE_SECOND = 1000;
  private CurrentTimeProvider currentTimeProvider;

  @Autowired
  public TimedRetry(CurrentTimeProvider currentTimeProvider) {
    this.currentTimeProvider = currentTimeProvider;
  }

  public boolean retryEverySecondUntil(long durationInSeconds, Supplier<Boolean> untilTrue) {
    long startTime = currentTimeProvider.currentTimeMillis();
    long currentTime;
    long endTime = startTime + ONE_SECOND * durationInSeconds;

    do {
      if (untilTrue.get()) {
        return true;
      }
      try {
        currentTimeProvider.sleep(ONE_SECOND);
      } catch (InterruptedException e) {
        // do nothing until we want to use InterruptedExceptions to
        // cause graceful shutdowns
      }

      currentTime = currentTimeProvider.currentTimeMillis();
    } while (currentTime < endTime);

    return false;
  }
}
