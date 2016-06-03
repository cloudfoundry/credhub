package io.pivotal.security.matcher;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;

public class ReflectiveEqualsMatcher<T> extends BaseMatcher<T> {

  private final T expectedValue;

  public ReflectiveEqualsMatcher(T equalArg) {
    expectedValue = equalArg;
  }

  @Override
  public boolean matches(Object actualValue) {
    return EqualsBuilder.reflectionEquals(actualValue, expectedValue);
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
