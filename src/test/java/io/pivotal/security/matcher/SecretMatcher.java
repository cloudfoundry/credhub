package io.pivotal.security.matcher;

import io.pivotal.security.model.Secret;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;

import java.util.Objects;

public class SecretMatcher extends BaseMatcher<Secret> {

  private final Secret expectedValue;

  public SecretMatcher(Secret equalArg) {
    expectedValue = equalArg;
  }

  @Override
  public boolean matches(Object item) {
    if (item == null) {
      return expectedValue == null;
    }

    if (item.getClass().isAssignableFrom(Secret.class)) {
      Secret secret = (Secret) item;
      return Objects.equals(secret.type, expectedValue.type)
          && Objects.equals(secret.value, expectedValue.value);
    }
    return false;
  }

  @Override
  public void describeTo(Description description) {
    description.appendValue(expectedValue);
  }

  @Factory
  public static Matcher<Secret> equalToSecret(Secret operand) {
    return new SecretMatcher(operand);
  }
}
