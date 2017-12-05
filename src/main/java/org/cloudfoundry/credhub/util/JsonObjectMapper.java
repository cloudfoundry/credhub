package org.cloudfoundry.credhub.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

import static com.fasterxml.jackson.databind.PropertyNamingStrategy.LOWER_CAMEL_CASE;
import static com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE;
import static org.cloudfoundry.credhub.util.TimeModuleFactory.createTimeModule;

public class JsonObjectMapper {

  private final ObjectMapper snakeCaseMapper;

  public JsonObjectMapper() {
    snakeCaseMapper = new ObjectMapper()
        .registerModule(createTimeModule())
        .setPropertyNamingStrategy(SNAKE_CASE);

  }

  public String writeValueAsString(Object object) throws JsonProcessingException {
    return snakeCaseMapper.writeValueAsString(object);
  }

  public <T> T deserializeBackwardsCompatibleValue(String stringValue, Class<T> type) throws IOException {
    try {
      return snakeCaseMapper.readValue(stringValue, type);
    } catch (Exception e) {
      ObjectMapper camelCaseMapper = new ObjectMapper()
          .registerModule(createTimeModule())
          .setPropertyNamingStrategy(LOWER_CAMEL_CASE);
      return camelCaseMapper.readValue(stringValue, type);
    }
  }

  public <T> T readValue(String stringValue, Class<T> type) throws IOException {
    return snakeCaseMapper.readValue(stringValue, type);
  }
}
