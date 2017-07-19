package io.pivotal.security.exceptions;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.Matchers.array;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class ParameterizedValidationExceptionTest {

  {
    it("extends validation exception", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException(
          "message.code", "foo");
      assertThat(subject, instanceOf(ParameterizedValidationException.class));
    });

    it("can take a message code without a parameter", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException(
          "message.code");
      assertThat(subject.getMessage(), equalTo("message.code"));
      assertThat(subject.getParameters(), equalTo(new Object[]{}));
    });

    it("takes a message code and parameter in the constructor", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException(
          "message.code", "foo");
      assertThat(subject.getMessage(), equalTo("message.code"));
      assertThat(subject.getParameters(), equalTo(new Object[]{"foo"}));
    });

    it("formats the output of JsonPath keys to remove '$' and '[', \', etc", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException(
          "message.code", "$['iasjdoiasd']");
      assertThat(subject.getParameters(), equalTo(new Object[]{"iasjdoiasd"}));
    });

    it("formats the output of JsonPath keys to put dots between nested keys", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException(
          "message.code", "$['parameters']['alternative_names']");
      assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names"}));

      subject = new ParameterizedValidationException("message.code",
          "$['parameters']['alternative_names'][*]");
      assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names.*"}));
    });

    it("formats the keys correctly when there are multiple parameters", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException(
          "message.code", new String[]{"$['parameters']['alternative_names']", "$['iasjdoiasd']"});
      assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names", "iasjdoiasd"}));

      subject = new ParameterizedValidationException("message.code",
          new String[]{"$['parameters']['alternative_names'][*]", "$['iasjdoiasd']"});
      assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names.*", "iasjdoiasd"}));
    });

    describe("getParameters", () -> {
      it("returns an array with the one param when present and null when no param is present",
          () -> {
            ParameterizedValidationException subject = new ParameterizedValidationException(
                "message.code", "foo");
            assertThat(subject.getParameters(), array(equalTo("foo")));

            subject = new ParameterizedValidationException("message.code");
            assertThat(subject.getParameters(), equalTo(new Object[]{}));
          });
    });
  }
}
