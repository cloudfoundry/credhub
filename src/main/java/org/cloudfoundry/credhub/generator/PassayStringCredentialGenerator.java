package org.cloudfoundry.credhub.generator;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;

@Component
public class PassayStringCredentialGenerator {

  public static final int DEFAULT_LENGTH = 30;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;
  private final PasswordGenerator passwordGenerator;

  @Autowired
  PassayStringCredentialGenerator(final PasswordGenerator passwordGenerator) {
    super();
    this.passwordGenerator = passwordGenerator;
  }

  public StringCredentialValue generateCredential(final StringGenerationParameters parameters) {
    final int passwordLength = normalizedLength(parameters.getLength());

    final List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(parameters);

    return new StringCredentialValue(
      passwordGenerator.generatePassword(passwordLength, characterRules));
  }

  private int normalizedLength(final int length) {
    int stringLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      stringLength = length;
    }

    return stringLength;
  }

}
