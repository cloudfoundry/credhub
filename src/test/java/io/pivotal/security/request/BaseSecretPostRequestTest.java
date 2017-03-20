package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.junit.Assert.assertFalse;

@RunWith(Spectrum.class)
public class BaseSecretPostRequestTest {

  {
    describe("isRegenerate flag", () -> {
      it("should default to false when missing", () -> {
        // language="JSON"
        BaseSecretPostRequest subject = JsonHelper.deserialize("{\n" +
            "  \"name\":\"/any/name\"\n" +
            "}", DefaultSecretGenerateRequest.class);

        assertFalse(subject.isRegenerate());
      });

      it("should default to false when set to null", () -> {
        // language="JSON"
        BaseSecretPostRequest subject = JsonHelper.deserialize("{\n" +
            "  \"name\":\"/any/name\",\n" +
            "  \"regenerate\":null\n" +
            "}", DefaultSecretGenerateRequest.class);

        assertFalse(subject.isRegenerate());
      });
    });
  }
}
