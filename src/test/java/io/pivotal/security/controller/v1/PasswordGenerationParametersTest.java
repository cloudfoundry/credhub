package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class PasswordGenerationParametersTest {

  @Autowired
  ObjectMapper objectMapper;

  {
    wireAndUnwire(this);

    it("is invalid when all charsets are excluded", () -> {
      assertThat(makeParameters(true, true, true, true).isValid(), equalTo(false));
      assertThat(makeParameters(true, true, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, true, false, true).isValid(), equalTo(true));
      assertThat(makeParameters(true, true, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, true, true).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, false, true).isValid(), equalTo(true));
      assertThat(makeParameters(true, false, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, true, true).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, false, true).isValid(), equalTo(true));
      assertThat(makeParameters(false, true, false, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, true, true).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, true, false).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, false, true).isValid(), equalTo(true));
      assertThat(makeParameters(false, false, false, false).isValid(), equalTo(true));
    });

    it("serializes via the object mapper to a compact representation with alphabetical keys", () -> {
      PasswordGenerationParameters parameters;

      parameters = makeParameters(false, false, false, false);
      assertThat(objectMapper.writeValueAsString(parameters), equalTo("{}"));

      parameters = makeParameters(true, true, true, false);
      assertThat(objectMapper.writeValueAsString(parameters), equalTo("{" +
          "\"exclude_lower\":true," +
          "\"exclude_special\":true," +
          "\"exclude_upper\":true" +
          "}"));
    });
  }

  private PasswordGenerationParameters makeParameters(boolean excludeLower, boolean excludeUpper, boolean excludeSpecial, boolean excludeNumber) {
    return new PasswordGenerationParameters()
          .setExcludeLower(excludeLower)
          .setExcludeUpper(excludeUpper)
          .setExcludeNumber(excludeNumber)
          .setExcludeSpecial(excludeSpecial);
  }
}
