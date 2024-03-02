package org.cloudfoundry.credhub.requests;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.fail;

public class RsaGenerationParametersTest {

  private RsaGenerationParameters subject;

  @BeforeEach
  public void beforeEach() {
    subject = new RsaGenerationParameters();
  }

  @Test
  public void defaultsToAReasonableKeyLength() {
    assertThat(subject.getKeyLength(), equalTo(2048));
  }

  @Test
  public void describe_acceptsCorrectKeyLengths() {
    subject.setKeyLength(2048);
    subject.validate();

    subject.setKeyLength(3072);
    subject.validate();

    subject.setKeyLength(4096);
    subject.validate();
  }

  @Test
  public void describe_withAnInvalidLength_ThrowsAnException() throws Exception {
    try {
      subject.setKeyLength(1024);
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.INVALID_KEY_LENGTH));
    }
  }
}
