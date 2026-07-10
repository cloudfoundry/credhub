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

    @Test
    fun whenDurationProvided_deserializesDurationAndPrependsSignedBy() {
        val request =
            JsonTestHelper.createObjectMapper().readValue(
                """
                {
                  "signed_by": "some-ca",
                  "duration": 730
                }
                """.trimIndent(),
                BulkRegenerateRequest::class.java,
            )

        MatcherAssert.assertThat(request.signedBy, Matchers.equalTo("/some-ca"))
        MatcherAssert.assertThat(request.duration, Matchers.equalTo(730))
    }
}
