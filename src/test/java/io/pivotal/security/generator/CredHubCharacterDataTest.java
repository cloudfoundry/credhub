package io.pivotal.security.generator;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import org.apache.commons.lang3.StringUtils;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class CredHubCharacterDataTest {

  {
    describe("#Special", () -> {
      it("includes only special characters", () -> {
        String specialCharacters = CredHubCharacterData.Special.getCharacters();

        assertThat(specialCharacters.contains("$"), equalTo(true));
        assertThat(specialCharacters.contains("!"), equalTo(true));

        assertThat(specialCharacters.matches("[^a-zA-Z0-9]"), equalTo(false));
        assertThat(StringUtils.containsWhitespace(specialCharacters), equalTo(false));
      });
    });

    describe("#Hex", () -> {
      it("includes only uppercase hex characters", () -> {
        String hexCharacters = CredHubCharacterData.Hex.getCharacters();

        assertThat(hexCharacters.matches("[A-F0-9]+"), equalTo(true));
      });
    });
  }
}
