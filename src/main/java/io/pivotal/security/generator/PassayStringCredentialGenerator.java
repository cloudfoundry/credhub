package io.pivotal.security.generator;

import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.credential.StringCredential;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PassayStringCredentialGenerator implements
    CredentialGenerator<StringGenerationParameters, StringCredential> {

  public static final int DEFAULT_LENGTH = 30;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;
  private final PasswordGenerator passwordGenerator;

  @Autowired
  PassayStringCredentialGenerator(PasswordGenerator passwordGenerator) {
    this.passwordGenerator = passwordGenerator;
  }

  @Override
  public StringCredential generateCredential(StringGenerationParameters parameters) {
    int passwordLength = normalizedLength(parameters.getLength());

    List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(parameters);

    return new StringCredential(passwordGenerator.generatePassword(passwordLength, characterRules));
  }

  private int normalizedLength(int length) {
    int stringLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      stringLength = length;
    }

    return stringLength;
  }

}
