package io.pivotal.security.request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static io.pivotal.security.helper.JsonTestHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

@RunWith(JUnit4.class)
public class RegenerateRequestTest {
  @Test
  public void whenNameIsMissing__isInvalid() {
    Set<ConstraintViolation<RegenerateRequest>> violations = deserializeAndValidate("{}",
        RegenerateRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
  }

}
