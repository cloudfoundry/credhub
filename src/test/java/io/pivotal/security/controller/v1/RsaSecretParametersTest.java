package io.pivotal.security.controller.v1;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.RsaGenerationParameters;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class RsaSecretParametersTest {

  private RsaGenerationParameters subject;

  {
    beforeEach(() -> {
      subject = new RsaGenerationParameters();
    });

    it("should default to a reasonable key length", () -> {
      assertThat(subject.getKeyLength(), equalTo(2048));
    });

    describe("validate", () -> {
      it("should accept correct key lengths", () -> {
        subject.setKeyLength(2048);
        subject.validate();

        subject.setKeyLength(3072);
        subject.validate();

        subject.setKeyLength(4096);
        subject.validate();
        //pass
      });

      itThrowsWithMessage("should throw if given an invalid length",
          ParameterizedValidationException.class, "error.invalid_key_length", () -> {
            subject.setKeyLength(1024);
            subject.validate();
          });
    });
  }
}
