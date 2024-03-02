package org.cloudfoundry.credhub.utils;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JsonObjectMapperTest {

  @Test
  public void writeValueAsString_convertsObjectToSnakeCaseJson() throws JsonProcessingException {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final String expectedResult = "{\"exclude_lower\":true,\"include_special\":true}";

    final String actualValue = new JsonObjectMapper().writeValueAsString(generationParameters);

    assertThat(actualValue, equalTo(expectedResult));
  }

  @Test
  public void deserializeBackwardsCompatibleValue_supportsSnakeCaseDeserialization() throws IOException {
    final String testSnakeCaseString = "{\"exclude_lower\":true,\"include_special\":true}";

    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
      .deserializeBackwardsCompatibleValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }

  @Test
  public void deserializeBackwardsCompatibleValue_supportsCamelCaseDeserialization() throws IOException {
    final String testSnakeCaseString = "{\"excludeLower\":true,\"includeSpecial\":true}";
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
      .deserializeBackwardsCompatibleValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }

  @Test
  public void readValue_shouldConvertJsonStringsInSnakeCaseToObjects() throws IOException {
    final String testSnakeCaseString = "{\"exclude_lower\":true,\"include_special\":true}";
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
      .readValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }
}
