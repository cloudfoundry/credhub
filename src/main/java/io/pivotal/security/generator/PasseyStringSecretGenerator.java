package io.pivotal.security.generator;

import io.pivotal.security.model.Secret;
import io.pivotal.security.model.StringSecret;
import io.pivotal.security.model.StringSecretParameters;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PasseyStringSecretGenerator implements SecretGenerator<StringSecretParameters, StringSecret> {

  public static final int DEFAULT_LENGTH = 20;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;

  @Autowired
  CharacterRuleProvider characterRuleProvider;

  @Autowired
  PasswordGenerator passwordGenerator;

  @Override
  public StringSecret generateSecret(StringSecretParameters parameters) {
    int passwordLength = normalizedSecretLength(parameters.getLength());

    List<CharacterRule> characterRules = characterRuleProvider.getCharacterRules(parameters);

    return new StringSecret(passwordGenerator.generatePassword(passwordLength, characterRules));
  }

  private int normalizedSecretLength(int length) {
    int passwordLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      passwordLength = length;
    }

    return passwordLength;
  }

}
