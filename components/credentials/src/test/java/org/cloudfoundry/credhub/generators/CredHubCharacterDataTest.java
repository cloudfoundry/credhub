package org.cloudfoundry.credhub.generators;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class CredHubCharacterDataTest {
  @Test
  public void special_includesOnlySpecialCharacters() {
    final String specialCharacters = CredHubCharacterData.SPECIAL.getCharacters();

    assertThat(specialCharacters.contains("$"), equalTo(true));
    assertThat(specialCharacters.contains("!"), equalTo(true));

    assertThat(specialCharacters.matches("[^a-zA-Z0-9]"), equalTo(false));
    assertThat(StringUtils.containsWhitespace(specialCharacters), equalTo(false));
  }

  @Test
  public void hex_includesOnlyHexCharacters() {
    final String hexCharacters = CredHubCharacterData.HEX.getCharacters();

    assertThat(hexCharacters.matches("[A-F0-9]+"), equalTo(true));
  }
}
