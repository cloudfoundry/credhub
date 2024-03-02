package org.cloudfoundry.credhub.generators;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.passay.PasswordGenerator;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class PassayStringCredentialValueGeneratorTest {

  private PasswordGenerator passwordGenerator;
  private PassayStringCredentialGenerator subject;

  @BeforeEach
  public void beforeEach() {
    passwordGenerator = mock(PasswordGenerator.class);
    subject = new PassayStringCredentialGenerator(passwordGenerator);
  }

  @Test
  public void canGenerateCredential() {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();

    when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
      .thenReturn("very-credential");

    final StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }

  @Test
  public void canGenerateCredentialWithSpecificLength() {
    when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-credential");

    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(42);

    final StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }

  @Test
  public void ignoresTooSmallLengthValues() {
    when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
      .thenReturn("very-credential");

    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(3);

    final StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }

  @Test
  public void ignoresTooLargeLengthValues() {
    when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
      .thenReturn("very-credential");

    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(201);

    final StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }
}
