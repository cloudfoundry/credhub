package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.collection.IsArrayContainingInOrder.arrayContaining;
import static org.hamcrest.collection.IsArrayWithSize.arrayWithSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsInstanceOf.*;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class ParameterizedValidationExceptionTest {
  {
    it("extends validation exception", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException("message.code", newArrayList("foo", "bar"));
      assertThat(subject, instanceOf(ParameterizedValidationException.class));
    });

    it("can take a message code without any parameters", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException("message.code");
      assertThat(subject.getMessage(), equalTo("message.code"));
      assertThat(subject.getParameters(), arrayWithSize(0));
    });

    it("takes a message code and parameters in the constructor", () -> {
      ParameterizedValidationException subject = new ParameterizedValidationException("message.code", newArrayList("foo", "bar"));
      assertThat(subject.getMessage(), equalTo("message.code"));
      assertThat(subject.getParameters(), arrayContaining("foo", "bar"));
    });
  }
}