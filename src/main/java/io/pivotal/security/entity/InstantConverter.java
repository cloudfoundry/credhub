package io.pivotal.security.entity;

import javax.persistence.AttributeConverter;
import java.time.Instant;

public class InstantConverter implements AttributeConverter<Instant, Long> {

  @Override
  public Long convertToDatabaseColumn(Instant attribute) {
    return attribute.getEpochSecond();
  }

  @Override
  public Instant convertToEntityAttribute(Long dbData) {
    return Instant.ofEpochSecond(dbData);
  }
}
