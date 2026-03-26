package org.cloudfoundry.credhub.utils;

import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JsonObjectMapperTest {

  @Test
  public void writeValueAsString_convertsObjectToSnakeCaseJson() {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final String expectedResult = "{\"exclude_lower\":true,\"include_special\":true}";

    final String actualValue = new JsonObjectMapper().writeValueAsString(generationParameters);

    assertThat(actualValue, equalTo(expectedResult));
  }

  @Test
  public void deserializeBackwardsCompatibleValue_supportsSnakeCaseDeserialization() {
    final String testSnakeCaseString = "{\"exclude_lower\":true,\"include_special\":true}";

    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
      .deserializeBackwardsCompatibleValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }

  @Test
  public void deserializeBackwardsCompatibleValue_supportsCamelCaseDeserialization() {
    final String testSnakeCaseString = "{\"excludeLower\":true,\"includeSpecial\":true}";
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
      .deserializeBackwardsCompatibleValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }

  @Test
  public void readValue_shouldConvertJsonStringsInSnakeCaseToObjects() {
    final String testSnakeCaseString = "{\"exclude_lower\":true,\"include_special\":true}";
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
      .readValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }
}
