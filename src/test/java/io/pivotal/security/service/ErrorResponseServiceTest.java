package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.view.ResponseError;
import org.junit.runner.RunWith;
import org.springframework.context.MessageSource;

import java.util.Locale;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class ErrorResponseServiceTest {
  private MessageSource messageSource;
  private ErrorResponseService subject;

  {
    beforeEach(() -> {
      messageSource = mock(MessageSource.class);
      when(messageSource.getMessage(eq("message1"), anyObject(), any(Locale.class)))
          .thenReturn("Message without params");
      when(messageSource.getMessage(eq("message2"), eq(new String[] { "foo" }), any(Locale.class)))
          .thenReturn("Message with params foo");
      subject = new ErrorResponseService(messageSource);
    });

    it("can create a parameterless ResponseError from a message key", () -> {
      ResponseError actual = subject.createErrorResponse("message1");
      assertThat(actual.getError(), equalTo("Message without params"));
    });

    it("can create a ResponseError from a message key and params", () -> {
      ParameterizedValidationException exception = new ParameterizedValidationException("message2", "foo");

      ResponseError actual = subject.createParameterizedErrorResponse(exception);
      assertThat(actual.getError(), equalTo("Message with params foo"));
    });
  }
}
