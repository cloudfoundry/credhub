package org.cloudfoundry.credhub.requests;

import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.ErrorMessages;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.hasViolationWithMessage;

@RunWith(JUnit4.class)
public class RegenerateRequestTest {
  @Test
  public void whenNameIsMissing__isInvalid() {
    final Set<ConstraintViolation<RegenerateRequest>> violations = deserializeAndValidate("{}",
      RegenerateRequest.class);

    MatcherAssert.assertThat(violations, Matchers.contains(hasViolationWithMessage(ErrorMessages.MISSING_NAME)));
  }

}
