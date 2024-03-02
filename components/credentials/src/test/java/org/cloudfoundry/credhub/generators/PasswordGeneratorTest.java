package org.cloudfoundry.credhub.generators;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PasswordGeneratorTest {
  private PasswordCredentialGenerator subject;

  private PassayStringCredentialGenerator passayStringCredentialGenerator;

  @BeforeEach
  public void beforeEach() {
    passayStringCredentialGenerator = mock(PassayStringCredentialGenerator.class);
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
