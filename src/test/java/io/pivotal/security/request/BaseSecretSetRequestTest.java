package io.pivotal.security.request;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;

@RunWith(Spectrum.class)
public class BaseSecretSetRequestTest {
  {
    describe("when type is not set", () -> {
      itThrows("should throw an JsonMappingException", JsonMappingException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
      });
    });

    describe("when type is an empty string", () -> {
      itThrows("should throw an InvalidTypeIdException", InvalidTypeIdException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
      });
    });

    describe("when type is unknown", () -> {
      itThrows("should throw an InvalidTypeIdException", InvalidTypeIdException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"moose\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
      });
    });
  }
}
