package io.pivotal.security.generator;

import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class PasseySecretGenerator implements SecretGenerator {

  @Autowired
  PasswordGenerator passwordGenerator;

  private List<CharacterRule> characterRules;

  PasseySecretGenerator() {
    CharacterData specialCharacters = new CharacterData() {
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

    characterRules = Arrays.asList(
        new CharacterRule(EnglishCharacterData.UpperCase),
        new CharacterRule(EnglishCharacterData.LowerCase),
        new CharacterRule(EnglishCharacterData.Digit),
        new CharacterRule(specialCharacters)
    );
  }

  @Override
  public String generateSecret() {
    return passwordGenerator.generatePassword(20, characterRules);
  }

}
