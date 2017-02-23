package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class PasswordGenerationParametersTest {

  @Autowired
  ObjectMapper objectMapper;

  {
    wireAndUnwire(this);

    it("is invalid when all charsets are excluded", () -> {
      assertThat(makeParameters(true, true, false, true, false).isValid(), equalTo(false));
      assertThat(makeParameters(true, true, false, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, true, true, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, true, true, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, false, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, false, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, true, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, true, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, false, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, false, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, true, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, true, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, false, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, false, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, true, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, true, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, true, false, true).isValid(), equalTo(true));
      assertThat(makeParameters(true, true, false, true, true).isValid(), equalTo(true));
    });

    it("serializes via the object mapper to a compact representation with alphabetical keys", () -> {
      PasswordGenerationParameters parameters = makeParameters(false, false, false, false, false);
      assertThat(objectMapper.writeValueAsString(parameters), equalTo("{}"));

      parameters = makeParameters(true, true, true, false, false);
      assertThat(objectMapper.writeValueAsString(parameters), equalTo("{" +
          "\"exclude_lower\":true," +
          "\"exclude_upper\":true," +
          "\"include_special\":true" +
          "}"));
    });
  }

  private PasswordGenerationParameters makeParameters(boolean excludeLower, boolean excludeUpper, boolean includeSpecial, boolean excludeNumber, boolean onlyHex) {
    return new PasswordGenerationParameters()
          .setExcludeLower(excludeLower)
          .setExcludeUpper(excludeUpper)
          .setExcludeNumber(excludeNumber)
          .setIncludeSpecial(includeSpecial)
          .setOnlyHex(onlyHex);
  }
}
