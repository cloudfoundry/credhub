package org.cloudfoundry.credhub.generator;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class CredHubCharacterDataTest {
  @Test
  public void special_includesOnlySpecialCharacters() {
    String specialCharacters = CredHubCharacterData.Special.getCharacters();

    assertThat(specialCharacters.contains("$"), equalTo(true));
    assertThat(specialCharacters.contains("!"), equalTo(true));

    assertThat(specialCharacters.matches("[^a-zA-Z0-9]"), equalTo(false));
    assertThat(StringUtils.containsWhitespace(specialCharacters), equalTo(false));
  }

  @Test
  public void hex_includesOnlyHexCharacters() {
    String hexCharacters = CredHubCharacterData.Hex.getCharacters();

    assertThat(hexCharacters.matches("[A-F0-9]+"), equalTo(true));
  }
}
