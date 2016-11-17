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
    return makeCalendar(Instant.now().toEpochMilli());
  }

  public static Calendar makeCalendar(long epochMilli) {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(epochMilli);
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
  }
}
