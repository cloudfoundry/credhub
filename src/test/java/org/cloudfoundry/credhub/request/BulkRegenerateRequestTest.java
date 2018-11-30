package org.cloudfoundry.credhub.request;

import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class BulkRegenerateRequestTest {
  @Test
  public void whenSignedByValueIsMissing__isInvalid() {
    Set<ConstraintViolation<BulkRegenerateRequest>> violations = JsonTestHelper.deserializeAndValidate("{}",
      BulkRegenerateRequest.class);

    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_signed_by")));
  }

}
