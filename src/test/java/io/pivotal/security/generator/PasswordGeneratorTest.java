package io.pivotal.security.generator;

import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PasswordGeneratorTest {
  private PasswordCredentialGenerator subject;

  private PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Before
  public void beforeEach() {
    passayStringCredentialGenerator = mock(PassayStringCredentialGenerator.class);
    subject = new PasswordCredentialGenerator(passayStringCredentialGenerator);
  }

  @Test
  public void generateCredential_usesTheParametersToGenerateAPassword() {
    final StringGenerationParameters stringGenerationParameters = mock(StringGenerationParameters.class);
    final StringCredential credential = new StringCredential("fake-generated-password");

    when(passayStringCredentialGenerator.generateCredential(stringGenerationParameters))
        .thenReturn(credential);
    
    assertThat(subject.generateCredential(stringGenerationParameters), equalTo(credential));
  }
}
