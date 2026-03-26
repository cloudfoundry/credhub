package org.cloudfoundry.credhub.utils;

import org.cloudfoundry.credhub.util.TimeModuleFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

public class JsonObjectMapper {

  private final JsonMapper snakeCaseMapper;

  public JsonObjectMapper() {
    super();
    snakeCaseMapper = JsonMapper.builder()
      .addModule(TimeModuleFactory.Companion.createTimeModule())
      .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
      .build();
  }

  public String writeValueAsString(final Object object) {
    return snakeCaseMapper.writeValueAsString(object);
  }

  public <T> T deserializeBackwardsCompatibleValue(final String stringValue, final Class<T> type) {
    try {
      return snakeCaseMapper.readValue(stringValue, type);
    } catch (final Exception e) {
      final JsonMapper camelCaseMapper = JsonMapper.builder()
        .addModule(TimeModuleFactory.Companion.createTimeModule())
        .propertyNamingStrategy(PropertyNamingStrategies.LOWER_CAMEL_CASE)
        .build();
      return camelCaseMapper.readValue(stringValue, type);
    }
  }

  public <T> T readValue(final String stringValue, final Class<T> type) {
    return snakeCaseMapper.readValue(stringValue, type);
  }

  public JsonNode readTree(final String stringValue) {
    return snakeCaseMapper.readTree(stringValue);
  }
}
