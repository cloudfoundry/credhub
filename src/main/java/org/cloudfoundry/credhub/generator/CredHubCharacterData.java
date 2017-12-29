package org.cloudfoundry.credhub.generator;

import org.passay.CharacterData;

public enum CredHubCharacterData implements CharacterData {
  // reusing library string that indicates whether a validation failed
  Special("INSUFFICIENT_SPECIAL", "!#$%&()*,-./:;<=>?@[\\]^_`{|}~"),
  Hex("error.insufficient_hex_alpha", "0123456789ABCDEF");

  private final String errorCode;
  private final String characters;

  CredHubCharacterData(final String code, final String charString) {
    errorCode = code;
    characters = charString;
  }

  @Override
  public String getErrorCode() {
    return errorCode;
  }

  @Override
  public String getCharacters() {
    return characters;
  }
}
