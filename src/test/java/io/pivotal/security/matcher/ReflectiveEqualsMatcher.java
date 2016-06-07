package io.pivotal.security.matcher;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;

public class ReflectiveEqualsMatcher<T> extends BaseMatcher<T> {

  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private final T expectedValue;

  public ReflectiveEqualsMatcher(T equalArg) {
    expectedValue = equalArg;
  }

  @Override
  public boolean matches(Object actualValue) {
    ObjectWriter objectWriter = OBJECT_MAPPER.writer().withDefaultPrettyPrinter();
    try {
      String actualJson = objectWriter.writeValueAsString(actualValue);
      String expectedJson = objectWriter.writeValueAsString(expectedValue);
      boolean wasEqual = actualJson.equals(expectedJson);
      if (!wasEqual) {
        System.out.println("\nactual: " + actualJson);
        System.out.println("expected: " + expectedJson);
      }
      return wasEqual;
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void describeTo(Description description) {
    description.appendValue(expectedValue);
  }

  @Factory
  public static <T> Matcher<T> reflectiveEqualTo(T operand) {
    return new ReflectiveEqualsMatcher<>(operand);
  }
}
