package io.pivotal.security.mapper;

import static com.google.common.collect.ImmutableSet.of;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import java.util.Set;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class RequestTranslatorTest {

  private ParseContext jsonPath;

  {
    RequestTranslator subject = new RequestTranslator() {

      @Override
      public void populateEntityFromJson(Object namedSecret, DocumentContext documentContext) {
      }

      @Override
      public Set<String> getValidKeys() {
        return of("$['foo']", "$['bar']", "$['baz']", "$['baz']['quux']", "$['dynamic']",
            "$['dynamic'][*]");
      }
    };

    beforeEach(() -> {
      jsonPath = new JsonContextFactory().getParseContext();
    });

    describe("populating entity from JSON", () -> {
      it("can accept all these valid keys", () -> {
        String requestBody = "{\"foo\":\"value\",\"bar\":\"\",\"baz\":{\"quux\":false}}";
        subject.validateJsonKeys(jsonPath.parse(requestBody));
      });

      it("rejects additional keys at top level", () -> {
        String requestJson = "{\"foo1\":\"value\",\"bar\":\"\",\"baz\":{\"quux\":false}}";
        doInvalidTest(subject, requestJson, "foo1");
      });

      it("rejects additional keys at a lower level", () -> {
        String requestJson = "{\"foo\":\"value\",\"bar\":\"\",\"baz\":{\"quux1\":false}}";
        doInvalidTest(subject, requestJson, "baz.quux1");
      });

      it("accepts references from a dynamic array", () -> {
        String requestJson = "{\"foo\":\"value\",\"bar\":\"\",\"dynamic\":[\"key1\",\"key2\"]}";
        subject.validateJsonKeys(jsonPath.parse(requestJson));
      });
    });

    describe("validation", () -> {
      it("should allow a single leading slash", () -> {
        RequestTranslator.validatePathName("/dont-do-this");
      });

      itThrows("validates path does not contain trailing slash",
          ParameterizedValidationException.class, () -> {
            RequestTranslator.validatePathName("dont-do-this/");
          });

      itThrows("validates path does not contain double slashes",
          ParameterizedValidationException.class, () -> {
            RequestTranslator.validatePathName("dont//do//this");
          });

      itThrows("validates path does not contain any invalid combination of slashes",
          ParameterizedValidationException.class, () -> {
            RequestTranslator.validatePathName("/dont//do//this/");
          });
    });

  }

  private void doInvalidTest(RequestTranslator subject, String requestBody, String invalidKey) {
    try {
      subject.validateJsonKeys(jsonPath.parse(requestBody));
      fail();
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_json_key"));
      assertThat(e.getParameter(), equalTo(invalidKey));
    }
  }
}
