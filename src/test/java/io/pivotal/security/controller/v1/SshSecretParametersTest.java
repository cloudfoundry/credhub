package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class SshSecretParametersTest {
  private SshSecretParameters subject;

  {
    beforeEach(() -> {
      subject = new SshSecretParameters();
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

      itThrowsWithMessage("should throw if given an invalid length", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
        subject.setKeyLength(1024);
        subject.validate();
      });
    });
  }
}
