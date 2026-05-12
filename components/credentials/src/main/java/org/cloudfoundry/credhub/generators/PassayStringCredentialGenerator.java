package org.cloudfoundry.credhub.generators;

import java.security.SecureRandom;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.passay.generate.PasswordGenerator;
import org.passay.rule.CharacterRule;

@Component
public class PassayStringCredentialGenerator {

  public static final int DEFAULT_LENGTH = 30;
  public static final int MIN_LENGTH = 4;
  public static final int MAX_LENGTH = 200;

  private final SecureRandom secureRandom;

  @Autowired
  PassayStringCredentialGenerator(final SecureRandom secureRandom) {
    super();
    this.secureRandom = secureRandom;
  }

  public StringCredentialValue generateCredential(final StringGenerationParameters parameters) {
    final int passwordLength = normalizedLength(parameters.getLength());
    final List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(parameters);
    return new StringCredentialValue(
      new PasswordGenerator(secureRandom, passwordLength, 2, characterRules).generate().toString());
  }

  private int normalizedLength(final int length) {
    int stringLength = DEFAULT_LENGTH;

    if (length >= MIN_LENGTH && length <= MAX_LENGTH) {
      stringLength = length;
    }

    return stringLength;
  }

}
