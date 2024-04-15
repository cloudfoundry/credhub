package org.cloudfoundry.credhub.requests;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.fail;

public class SshGenerationParametersTest {
  private SshGenerationParameters subject;

  @BeforeEach
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
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.INVALID_KEY_LENGTH));
    }
  }
}
