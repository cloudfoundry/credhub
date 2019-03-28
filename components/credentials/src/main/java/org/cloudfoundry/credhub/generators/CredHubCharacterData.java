package org.cloudfoundry.credhub.generators;

import org.cloudfoundry.credhub.ErrorMessages;
import org.passay.CharacterData;

public enum CredHubCharacterData implements CharacterData {
  // reusing library string that indicates whether a validation failed
  SPECIAL("INSUFFICIENT_SPECIAL", "!#$%&()*,-./:;<=>?@[\\]^_`{|}~"),
  HEX(ErrorMessages.INSUFFICIENT_HEX_ALPHA, "0123456789ABCDEF");

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
