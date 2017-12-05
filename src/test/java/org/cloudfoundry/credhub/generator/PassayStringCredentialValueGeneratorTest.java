package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;

import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(JUnit4.class)
public class PassayStringCredentialValueGeneratorTest {

  private PasswordGenerator passwordGenerator;
  private PassayStringCredentialGenerator subject;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;


  @Before
  public void beforeEach() {
    passwordGenerator = mock(PasswordGenerator.class);
    subject = new PassayStringCredentialGenerator(passwordGenerator);
  }

  @Test
  public void canGenerateCredential() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();

    when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), any(List.class)))
        .thenReturn("very-credential");

    StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }

  @Test
  public void canGenerateCredentialWithSpecificLength() {
    when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-credential");

    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(42);

    StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }

  @Test
  public void ignoresTooSmallLengthValues() {
    when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
        .thenReturn("very-credential");

    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(3);

    StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }

  @Test
  public void ignoresTooLargeLengthValues() {
    when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
        .thenReturn("very-credential");

    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(201);

    StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
    assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
  }
}
