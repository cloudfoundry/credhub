package org.cloudfoundry.credhub.util;

import java.time.Instant;
import javax.persistence.AttributeConverter;

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
