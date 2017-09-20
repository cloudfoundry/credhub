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
public class BulkRegenerateRequestTest {
  @Test
  public void whenSignedByValueIsMissing__isInvalid() {
    Set<ConstraintViolation<BulkRegenerateRequest>> violations = deserializeAndValidate("{}",
        BulkRegenerateRequest.class);

    assertThat(violations, contains(hasViolationWithMessage("error.missing_signed_by")));
  }

}
