package io.pivotal.security.util;

import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Calendar;
import java.util.TimeZone;

@Component
public class CurrentTimeProvider implements DateTimeProvider {

  @Override
  public Calendar getNow() {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(Instant.now().toEpochMilli());
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
  }
}