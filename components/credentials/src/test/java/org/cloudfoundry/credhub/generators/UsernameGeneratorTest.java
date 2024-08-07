package org.cloudfoundry.credhub.generators;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UsernameGeneratorTest {
  private UsernameGenerator subject;
  private PassayStringCredentialGenerator passayStringCredentialGenerator;

  @BeforeEach
  public void beforeEach() {
    passayStringCredentialGenerator = mock(PassayStringCredentialGenerator.class);
    subject = new UsernameGenerator(passayStringCredentialGenerator);
  }

  @Test
  public void generateCredential_generatesACredential() {
    final StringCredentialValue expected = new StringCredentialValue("fake-credential");
    when(passayStringCredentialGenerator.generateCredential(any(StringGenerationParameters.class)))
      .thenReturn(expected);

    final StringCredentialValue credential = subject.generateCredential();

    assertThat(credential, equalTo(expected));
  }

  @Test
  public void generateCredential_usesAppropriateGenerationParameters() {
    final ArgumentCaptor<StringGenerationParameters> captor = ArgumentCaptor.forClass(StringGenerationParameters.class);

    subject.generateCredential();

    verify(passayStringCredentialGenerator, times(1))
      .generateCredential(captor.capture());

    final StringGenerationParameters actual = captor.getValue();

    assertThat(actual.getLength(), equalTo(20));
    assertThat(actual.isExcludeLower(), equalTo(false));
    assertThat(actual.isExcludeUpper(), equalTo(false));
    assertThat(actual.isExcludeNumber(), equalTo(true));
    assertThat(actual.isIncludeSpecial(), equalTo(false));
  }
}
