package io.pivotal.security.generator;

import io.pivotal.security.model.SecretParameters;
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

  public static final int DEFAULT_LENGTH = 20;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;

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
  public String generateSecret(SecretParameters parameters) {
    int passwordLength = normalizedSecretLength(parameters.getLength());

    return passwordGenerator.generatePassword(passwordLength, characterRules);
  }

  private int normalizedSecretLength(int length) {
    int passwordLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      passwordLength = length;
    }

    return passwordLength;
  }

}
