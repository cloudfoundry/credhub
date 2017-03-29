package io.pivotal.security.generator;

import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import java.util.List;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PassayStringSecretGenerator implements
    SecretGenerator<PasswordGenerationParameters, Password> {

  public static final int DEFAULT_LENGTH = 30;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;
  private final PasswordGenerator passwordGenerator;

  @Autowired
  PassayStringSecretGenerator(PasswordGenerator passwordGenerator) {
    this.passwordGenerator = passwordGenerator;
  }

  @Override
  public Password generateSecret(PasswordGenerationParameters parameters) {
    int passwordLength = normalizedSecretLength(parameters.getLength());

    List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(parameters);

    return new Password(passwordGenerator.generatePassword(passwordLength, characterRules));
  }

  private int normalizedSecretLength(int length) {
    int passwordLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      passwordLength = length;
    }

    return passwordLength;
  }

}
