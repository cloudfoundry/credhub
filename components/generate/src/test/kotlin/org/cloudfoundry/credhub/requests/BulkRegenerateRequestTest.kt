package org.cloudfoundry.credhub.requests

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.helpers.JsonTestHelper
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.jupiter.api.Test

class BulkRegenerateRequestTest {
    @Test
    fun whenSignedByValueIsMissing__isInvalid() {
        val violations =
            JsonTestHelper.deserializeAndValidate(
                "{}",
                BulkRegenerateRequest::class.java,
            )

        MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage(ErrorMessages.MISSING_SIGNED_BY)))
    }
}
