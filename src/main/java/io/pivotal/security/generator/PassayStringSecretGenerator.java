package io.pivotal.security.generator;

import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.secret.StringSecret;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PassayStringSecretGenerator implements
    SecretGenerator<StringGenerationParameters, StringSecret> {

  public static final int DEFAULT_LENGTH = 30;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;
  private final PasswordGenerator passwordGenerator;

  @Autowired
  PassayStringSecretGenerator(PasswordGenerator passwordGenerator) {
    this.passwordGenerator = passwordGenerator;
  }

  @Override
  public StringSecret generateSecret(StringGenerationParameters parameters) {
    int passwordLength = normalizedSecretLength(parameters.getLength());

    List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(parameters);

    return new StringSecret(passwordGenerator.generatePassword(passwordLength, characterRules));
  }

  private int normalizedSecretLength(int length) {
    int stringLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      stringLength = length;
    }

    return stringLength;
  }

}
