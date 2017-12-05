package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(JUnit4.class)
public class RsaSshGenerationParametersTest {
  @Test
  public void validate_withInvalidKeyLength_throwsAnException() {
    try {
      RsaSshGenerationParameters subject = new RsaSshGenerationParameters();
      subject.setKeyLength(1337);
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_key_length"));
    }
  }
}
