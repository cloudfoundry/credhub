package io.pivotal.security.helper;

import io.pivotal.security.util.CurrentTimeProvider;

import java.time.Instant;
import java.util.Calendar;

public class FakeCurrentTimeProvider extends CurrentTimeProvider {

  private long timeMillis;

  public void setCurrentTimeMillis(long timeMillis) {
    this.timeMillis = timeMillis;
  }

  @Override
  public Calendar getNow() {
    throw new UnsupportedOperationException("not yet implemented");
  }

  @Override
  public Instant getInstant() {
    throw new UnsupportedOperationException("not yet implemented");
  }

  @Override
  public long currentTimeMillis() {
    return timeMillis;
  }

  @Override
  public void sleep(long sleepTimeInMillis) throws InterruptedException {
    timeMillis += sleepTimeInMillis;
  }
}
