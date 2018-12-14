package org.cloudfoundry.credhub.util;

import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class TimedRetry {

  public static final int ONE_SECOND = 1000;
  private final CurrentTimeProvider currentTimeProvider;

  @Autowired
  public TimedRetry(final CurrentTimeProvider currentTimeProvider) {
    super();
    this.currentTimeProvider = currentTimeProvider;
  }

  public boolean retryEverySecondUntil(final long durationInSeconds, final Supplier<Boolean> untilTrue) {
    final long startTime = currentTimeProvider.currentTimeMillis();
    long currentTime;
    final long endTime = startTime + ONE_SECOND * durationInSeconds;

    do {
      if (untilTrue.get()) {
        return true;
      }
      try {
        currentTimeProvider.sleep(ONE_SECOND);
      } catch (final InterruptedException e) {
        // do nothing until we want to use InterruptedExceptions to
        // cause graceful shutdowns
      }

      currentTime = currentTimeProvider.currentTimeMillis();
    } while (currentTime < endTime);

    return false;
  }
}
