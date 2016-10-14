package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CharacterRuleProvider {

  private CharacterData specialCharacters;
  private CharacterData hexCharacters;

  public CharacterRuleProvider() {
    specialCharacters = new CharacterData() {
      @Override
      public String getErrorCode() {
        // reusing library string that indicates whether a validation failed
        return "INSUFFICIENT_SPECIAL";
      }

      @Override
      public String getCharacters() {
        return "!\"#$%&'()*,-./:;<=>?@[\\]^_`{|}~";
      }
    };

    hexCharacters = new CharacterData() {
      @Override
      public String getErrorCode() {
        return "error.insufficient_hex_alpha";
      }

      @Override
      public String getCharacters() {
        return "0123456789ABCDEF";
      }
    };
  }

  public List<CharacterRule> getCharacterRules(PasswordGenerationParameters parameters) {
    List<CharacterRule> characterRules = new ArrayList<>();

    if (parameters.isOnlyHex()) {
      characterRules.add(new CharacterRule(EnglishCharacterData.Digit));
      characterRules.add(new CharacterRule(hexCharacters));
    } else {
      if (!parameters.isExcludeSpecial()) {
        characterRules.add(new CharacterRule(specialCharacters));
      }

      if (!parameters.isExcludeNumber()) {
        characterRules.add(new CharacterRule(EnglishCharacterData.Digit));
      }

      if (!parameters.isExcludeUpper()) {
        characterRules.add(new CharacterRule(EnglishCharacterData.UpperCase));
      }

      if (!parameters.isExcludeLower()) {
        characterRules.add(new CharacterRule(EnglishCharacterData.LowerCase));
      }
    }

    return characterRules;
  }

}
