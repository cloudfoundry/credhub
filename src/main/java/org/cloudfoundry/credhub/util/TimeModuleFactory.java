package org.cloudfoundry.credhub.util;

import static java.time.format.DateTimeFormatter.ofPattern;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class TimeModuleFactory {

  private static final DateTimeFormatter TIMESTAMP_FORMAT = ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

  public static JavaTimeModule createTimeModule() {
    JavaTimeModule javaTimeModule = new JavaTimeModule();

    javaTimeModule.addSerializer(Instant.class, new JsonSerializer<Instant>() {
      @Override
      public void serialize(Instant value, JsonGenerator gen, SerializerProvider serializers)
          throws IOException {
        gen.writeString(ZonedDateTime.ofInstant(value, ZoneId.of("UTC")).format(TIMESTAMP_FORMAT));
      }
    });

    return javaTimeModule;
  }
}
