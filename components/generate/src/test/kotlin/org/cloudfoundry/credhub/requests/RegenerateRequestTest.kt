package org.cloudfoundry.credhub.requests

import jakarta.validation.ConstraintViolation
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.deserializeAndValidate
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.hasViolationWithMessage
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class RegenerateRequestTest {
    @Test
    fun whenNameIsMissing__isInvalid() {
        val violations =
            deserializeAndValidate<RegenerateRequest>(
                "{}",
                RegenerateRequest::class.java,
            )

        MatcherAssert.assertThat<Set<ConstraintViolation<RegenerateRequest>>>(
            violations,
            Matchers.contains(hasViolationWithMessage(ErrorMessages.MISSING_NAME)),
        )
    }
}
