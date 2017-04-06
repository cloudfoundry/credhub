package io.pivotal.security.request;

import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class RsaSshGenerationParametersTest {
  {
    itThrowsWithMessage("#validate", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
      RsaSshGenerationParameters subject = new RsaSshGenerationParameters();
      subject.setKeyLength(1337);
      subject.validate();
    });
  }
}
