package io.pivotal.security.generator;

import io.pivotal.security.request.PasswordGenerationParameters;
import java.util.ArrayList;
import java.util.List;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;

public class CharacterRuleProvider {

  public static List<CharacterRule> getCharacterRules(PasswordGenerationParameters parameters) {
    List<CharacterRule> characterRules = new ArrayList<>();

    if (parameters.isOnlyHex()) {
      characterRules.add(new CharacterRule(CredHubCharacterData.Hex));
    } else {
      if (parameters.isIncludeSpecial()) {
        characterRules.add(new CharacterRule(CredHubCharacterData.Special));
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
