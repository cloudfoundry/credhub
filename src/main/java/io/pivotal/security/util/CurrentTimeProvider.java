package io.pivotal.security.util;

import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Calendar;
import java.util.TimeZone;

@Component
public class CurrentTimeProvider implements DateTimeProvider {

  private Instant overrideTime;

  public Instant getCurrentTime() {
    if (overrideTime == null) {
      return Instant.now();
    } else {
      return overrideTime;
    }
  }

  public void setOverrideTime(Instant override) {
    overrideTime = override;
  }

  public void reset() {
    overrideTime = null;
  }

  @Override
  public Calendar getNow() {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(getCurrentTime().toEpochMilli());
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
  }
}