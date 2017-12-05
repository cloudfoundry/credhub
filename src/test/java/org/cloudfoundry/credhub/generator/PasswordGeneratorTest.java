package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
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
  private UserContext userContext;

  @Before
  public void beforeEach() {
    passayStringCredentialGenerator = mock(PassayStringCredentialGenerator.class);
    userContext = mock(UserContext.class);
    subject = new PasswordCredentialGenerator(passayStringCredentialGenerator);
  }

  @Test
  public void generateCredential_usesTheParametersToGenerateAPassword() {
    final StringGenerationParameters stringGenerationParameters = mock(StringGenerationParameters.class);
    final StringCredentialValue credential = new StringCredentialValue("fake-generated-password");

    when(passayStringCredentialGenerator.generateCredential(stringGenerationParameters))
        .thenReturn(credential);
    
    assertThat(subject.generateCredential(stringGenerationParameters), equalTo(credential));
  }
}
