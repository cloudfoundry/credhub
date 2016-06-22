package io.pivotal.security.model;

import org.springframework.data.auditing.DateTimeProvider;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Calendar;
import java.util.TimeZone;

public class CurrentTimeProvider implements DateTimeProvider {

  private LocalDateTime overrideTime;

  public LocalDateTime getCurrentTime() {
    if (overrideTime == null) {
      return LocalDateTime.now(ZoneId.of("UTC"));
    } else {
      return overrideTime;
    }
  }

  public void setOverrideTime(LocalDateTime override) {
    overrideTime = override;
  }

  public void reset() {
    overrideTime = null;
  }

  @Override
  public Calendar getNow() {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(getCurrentTime().toInstant(ZoneOffset.UTC).toEpochMilli());
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
  }
}