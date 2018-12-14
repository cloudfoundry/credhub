package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class StringGenerationParametersTest {

  private final ObjectMapper objectMapper = JsonTestHelper.createObjectMapper();

  @Test
  public void whenAllCharsetsAreExcluded_isInvalid() {
    assertThat(makeParameters(true, true, true, true).isValid(), is(true));
    assertThat(makeParameters(true, true, true, false).isValid(), is(true));
    assertThat(makeParameters(true, true, false, true).isValid(), is(false));
    assertThat(makeParameters(true, true, false, false).isValid(), is(true));
    assertThat(makeParameters(true, false, false, true).isValid(), is(true));
    assertThat(makeParameters(true, false, false, false).isValid(), is(true));
    assertThat(makeParameters(true, false, true, true).isValid(), is(true));
    assertThat(makeParameters(true, false, true, false).isValid(), is(true));
    assertThat(makeParameters(false, true, false, true).isValid(), is(true));
    assertThat(makeParameters(false, true, false, false).isValid(), is(true));
    assertThat(makeParameters(false, true, true, true).isValid(), is(true));
    assertThat(makeParameters(false, true, true, false).isValid(), is(true));
    assertThat(makeParameters(false, false, false, true).isValid(), is(true));
    assertThat(makeParameters(false, false, false, false).isValid(), is(true));
    assertThat(makeParameters(false, false, true, true).isValid(), is(true));
    assertThat(makeParameters(false, false, true, false).isValid(), is(true));
  }

  @Test
  public void serializesViaTheObjectMapperToACompactRepresentationWithAlphabeticalKeys() throws Exception {
    StringGenerationParameters parameters = makeParameters(false, false, false, false);
    assertThat(objectMapper.writeValueAsString(parameters), equalTo("{}"));

    parameters = makeParameters(true, true, true, false);
    assertThat(objectMapper.writeValueAsString(parameters), equalTo("{"
      + "\"exclude_lower\":true,"
      + "\"exclude_upper\":true,"
      + "\"include_special\":true"
      + "}"));
  }

  private StringGenerationParameters makeParameters(
    final boolean excludeLower,
    final boolean excludeUpper,
    final boolean includeSpecial,
    final boolean excludeNumber
  ) {
    StringGenerationParameters stringGenerationParameters = new StringGenerationParameters();
    stringGenerationParameters.setLength(30);
    stringGenerationParameters.setExcludeLower(excludeLower);
    stringGenerationParameters.setExcludeUpper(excludeUpper);
    stringGenerationParameters.setExcludeNumber(excludeNumber);
    stringGenerationParameters.setIncludeSpecial(includeSpecial);

    return stringGenerationParameters;
  }
}
