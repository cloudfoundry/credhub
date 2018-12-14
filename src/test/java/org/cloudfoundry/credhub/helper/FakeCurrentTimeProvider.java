package org.cloudfoundry.credhub.helper;

import java.time.Instant;
import java.time.temporal.TemporalAccessor;
import java.util.Optional;

import org.cloudfoundry.credhub.util.CurrentTimeProvider;

public class FakeCurrentTimeProvider extends CurrentTimeProvider {

  private long timeMillis;

  public void setCurrentTimeMillis(final long timeMillis) {
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
  public void sleep(final long sleepTimeInMillis) throws InterruptedException {
    timeMillis += sleepTimeInMillis;
  }
}
