package org.cloudfoundry.credhub.helper;

import org.cloudfoundry.credhub.util.CurrentTimeProvider;

import java.time.Instant;
import java.time.temporal.TemporalAccessor;
import java.util.Optional;

public class FakeCurrentTimeProvider extends CurrentTimeProvider {

  private long timeMillis;

  public void setCurrentTimeMillis(long timeMillis) {
    this.timeMillis = timeMillis;
  }

  @Override
  public Optional<TemporalAccessor> getNow() {
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
