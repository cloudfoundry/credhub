package org.cloudfoundry.credhub.util;

import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.TemporalAccessor;
import java.util.Calendar;
import java.util.Optional;
import java.util.TimeZone;

@Component
public class CurrentTimeProvider implements DateTimeProvider {

//  public static Calendar makeCalendar(long epochMilli) {
//    Calendar.Builder builder = new Calendar.Builder();
//    builder.setInstant(epochMilli);
//    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
//    return builder.build();
//  }

  @Override
  public Optional<TemporalAccessor> getNow() {
    return Optional.of(getInstant());
  }

  public Instant getInstant() {
    return Instant.now();
  }

  public long currentTimeMillis() {
    return System.currentTimeMillis();
  }

  public void sleep(long sleepTimeInMillis) throws InterruptedException {
      Thread.sleep(sleepTimeInMillis);
  }
}
