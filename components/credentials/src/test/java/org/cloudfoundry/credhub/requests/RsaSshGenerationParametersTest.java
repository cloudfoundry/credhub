package org.cloudfoundry.credhub.requests;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.fail;

public class RsaSshGenerationParametersTest {
  @Test
  public void validate_withInvalidKeyLength_throwsAnException() {
    try {
      final RsaSshGenerationParameters subject = new RsaSshGenerationParameters();
      subject.setKeyLength(1337);
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.INVALID_KEY_LENGTH));
    }
  }
}
