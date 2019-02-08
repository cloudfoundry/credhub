package org.cloudfoundry.credhub.utils;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.util.TimeModuleFactory;

import static com.fasterxml.jackson.databind.PropertyNamingStrategy.LOWER_CAMEL_CASE;
import static com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE;

public class JsonObjectMapper {

  private final ObjectMapper snakeCaseMapper;

  public JsonObjectMapper() {
    super();
    snakeCaseMapper = new ObjectMapper()
      .registerModule(TimeModuleFactory.createTimeModule())
      .setPropertyNamingStrategy(SNAKE_CASE);

  }

  public String writeValueAsString(final Object object) throws JsonProcessingException {
    return snakeCaseMapper.writeValueAsString(object);
  }

  public <T> T deserializeBackwardsCompatibleValue(final String stringValue, final Class<T> type) throws IOException {
    try {
      return snakeCaseMapper.readValue(stringValue, type);
    } catch (final Exception e) {
      final ObjectMapper camelCaseMapper = new ObjectMapper()
        .registerModule(TimeModuleFactory.createTimeModule())
        .setPropertyNamingStrategy(LOWER_CAMEL_CASE);
      return camelCaseMapper.readValue(stringValue, type);
    }
  }

  public <T> T readValue(final String stringValue, final Class<T> type) throws IOException {
    return snakeCaseMapper.readValue(stringValue, type);
  }

  public JsonNode readTree(final String stringValue) throws IOException {
    return snakeCaseMapper.readTree(stringValue);
  }
}
