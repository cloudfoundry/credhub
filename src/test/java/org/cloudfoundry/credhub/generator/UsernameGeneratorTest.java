package org.cloudfoundry.credhub.generator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

@RunWith(JUnit4.class)
public class UsernameGeneratorTest {
  private UsernameGenerator subject;
  private PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Before
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
    ArgumentCaptor<StringGenerationParameters> captor = ArgumentCaptor.forClass(StringGenerationParameters.class);

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
