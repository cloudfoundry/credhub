package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static junit.framework.TestCase.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class SshGenerationParametersTest {
  private SshGenerationParameters subject;

  @Before
  public void beforeEach() {
    subject = new SshGenerationParameters();
  }

  @Test
  public void defaultsToAReasonableKeyLength() {
    assertThat(subject.getKeyLength(), equalTo(2048));
  }

  @Test
  public void validate_allowsCorrectKeyLengths() {
    subject.setKeyLength(2048);
    subject.validate();

    subject.setKeyLength(3072);
    subject.validate();

    subject.setKeyLength(4096);
    subject.validate();
    //pass
  }

  @Test
  public void validate_throwsIfGivenAnInvalidLength() {
    try {
      subject.setKeyLength(1024);
      subject.validate();

      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_key_length"));
    }
  }
}
