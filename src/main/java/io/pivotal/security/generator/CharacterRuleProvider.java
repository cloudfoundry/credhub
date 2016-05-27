package io.pivotal.security.generator;

import io.pivotal.security.model.SecretParameters;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CharacterRuleProvider {

  private CharacterData specialCharacters;

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
  }

  public List<CharacterRule> getCharacterRules(SecretParameters parameters) {
    List<CharacterRule> characterRules = new ArrayList<>();

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

    return characterRules;
  }

}
