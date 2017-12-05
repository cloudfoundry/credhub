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
public class BulkRegenerateRequestTest {
  @Test
  public void whenSignedByValueIsMissing__isInvalid() {
    Set<ConstraintViolation<BulkRegenerateRequest>> violations = JsonTestHelper.deserializeAndValidate("{}",
        BulkRegenerateRequest.class);

    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_signed_by")));
  }

}
