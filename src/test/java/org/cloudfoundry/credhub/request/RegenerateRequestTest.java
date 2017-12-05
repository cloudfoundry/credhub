package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Set;
import javax.validation.ConstraintViolation;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

@RunWith(JUnit4.class)
public class RegenerateRequestTest {
  @Test
  public void whenNameIsMissing__isInvalid() {
    Set<ConstraintViolation<RegenerateRequest>> violations = JsonTestHelper.deserializeAndValidate("{}",
        RegenerateRequest.class);

    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_name")));
  }

}
