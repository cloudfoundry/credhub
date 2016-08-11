package io.pivotal.security.entity;

import javax.persistence.AttributeConverter;
import java.time.Instant;

public class InstantMillisecondsConverter implements AttributeConverter<Instant, Long> {

  @Override
  public Long convertToDatabaseColumn(Instant attribute) {
    return attribute.toEpochMilli();
  }

  @Override
  public Instant convertToEntityAttribute(Long dbData) {
    return Instant.ofEpochMilli(dbData);
  }
}
