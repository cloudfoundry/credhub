package org.cloudfoundry.credhub.generators;

import java.security.SecureRandom;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;


public class PassayStringCredentialValueGeneratorTest {

  private PassayStringCredentialGenerator subject;

  @BeforeEach
  public void beforeEach() {
    subject = new PassayStringCredentialGenerator(new SecureRandom());
  }

  @Test
  public void canGenerateCredential() {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    final StringCredentialValue result = subject.generateCredential(generationParameters);
    assertThat(result.getStringCredential().length(), equalTo(subject.DEFAULT_LENGTH));
  }

  @Test
  public void canGenerateCredentialWithSpecificLength() {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(42);
    final StringCredentialValue result = subject.generateCredential(generationParameters);
    assertThat(result.getStringCredential().length(), equalTo(42));
  }

  @Test
  public void ignoresTooSmallLengthValues() {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(3);
    final StringCredentialValue result = subject.generateCredential(generationParameters);
    assertThat(result.getStringCredential().length(), equalTo(subject.DEFAULT_LENGTH));
  }

  @Test
  public void ignoresTooLargeLengthValues() {
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setLength(201);
    final StringCredentialValue result = subject.generateCredential(generationParameters);
    assertThat(result.getStringCredential().length(), equalTo(subject.DEFAULT_LENGTH));
  }
}
