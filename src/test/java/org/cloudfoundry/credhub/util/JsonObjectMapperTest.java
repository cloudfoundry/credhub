package org.cloudfoundry.credhub.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class JsonObjectMapperTest {

  @Test
  public void writeValueAsString_convertsObjectToSnakeCaseJson() throws JsonProcessingException {
    final StringGenerationParameters generationParameters = new StringGenerationParameters().setExcludeLower(true).setIncludeSpecial(true);
    String expectedResult = "{\"exclude_lower\":true,\"include_special\":true}";

    final String actualValue = new JsonObjectMapper().writeValueAsString(generationParameters);

    assertThat(actualValue, equalTo(expectedResult));
  }

  @Test
  public void deserializeBackwardsCompatibleValue_supportsSnakeCaseDeserialization() throws IOException {
    final String testSnakeCaseString = "{\"exclude_lower\":true,\"include_special\":true}";
    StringGenerationParameters generationParameters = new StringGenerationParameters().setExcludeLower(true).setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
        .deserializeBackwardsCompatibleValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }

  @Test
  public void deserializeBackwardsCompatibleValue_supportsCamelCaseDeserialization() throws IOException {
    final String testSnakeCaseString = "{\"excludeLower\":true,\"includeSpecial\":true}";
    StringGenerationParameters generationParameters = new StringGenerationParameters().setExcludeLower(true).setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
        .deserializeBackwardsCompatibleValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }

  @Test
  public void readValue_shouldConvertJsonStringsInSnakeCaseToObjects() throws IOException {
    final String testSnakeCaseString = "{\"exclude_lower\":true,\"include_special\":true}";
    StringGenerationParameters generationParameters = new StringGenerationParameters().setExcludeLower(true).setIncludeSpecial(true);

    final StringGenerationParameters actualGenerationParameters = new JsonObjectMapper()
        .readValue(testSnakeCaseString, StringGenerationParameters.class);

    assertThat(generationParameters, equalTo(actualGenerationParameters));
  }
}
