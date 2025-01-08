package org.cloudfoundry.credhub.requests

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.helpers.JsonTestHelper
import org.hamcrest.MatcherAssert
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.collection.IsIterableContainingInOrder
import org.hamcrest.core.IsEqual.equalTo
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class PermissionsV2RequestTest {
    @Test
    fun whenPathEndsWithSlash_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "some-path/",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.INVALID_SLASH_IN_PATH),
            ),
        )
    }

    @Test
    fun whenPathContainsDoubleSlash_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "some//path",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.INVALID_SLASH_IN_PATH),
            ),
        )
    }

    @Test
    fun whenPathIsNotSet_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_PATH),
            ),
        )
    }

    @Test
    fun whenActorIsNotSet_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "path": "some-path",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACTOR),
            ),
        )
    }

    @Test
    fun whenOperationsAreNotSet_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "some-path"
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_OPERATIONS),
            ),
        )
    }

    @Test
    fun whenPathIsEmpty_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_PATH),
            ),
        )
    }

    @Test
    fun whenActorIsEmpty_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "",
              "path": "some-path",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACTOR),
            ),
        )
    }

    @Test
    fun whenOperationsAreEmpty_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "some-path",
              "operations": []
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_OPERATIONS),
            ),
        )
    }

    @Test
    fun whenPathIsJustASlash_shouldBeInvalid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "/",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(
            violations,
            IsIterableContainingInOrder.contains(
                JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.MISSING_PATH),
            ),
        )
    }

    @Test
    fun whenPathContainsInvalidCharacter_shouldBeInvalid() {
        for (invalidCharacter in charArrayOf(' ', '\\', '*')) {
            // language=JSON
            val json =
                """
                {
                  "actor": "some-actor",
                  "path": "test${invalidCharacter}test",
                  "operations": ["read", "write"]
                }
                """.trimIndent()

            val violations =
                JsonTestHelper
                    .deserializeAndValidate(json, PermissionsV2Request::class.java)

            assertThat(violations.size, equalTo(1))
            MatcherAssert.assertThat(
                violations,
                IsIterableContainingInOrder.contains(
                    JsonTestHelper.hasViolationWithMessage(ErrorMessages.Permissions.INVALID_CHARACTER_IN_PATH),
                ),
            )
        }
    }

    @Test
    fun whenPathContainsSpecialCharacters_shouldBeValid() {
        for (specialCharacter in charArrayOf('.', ':', '(', ')', '[', ']', '+')) {
            // language=JSON
            val json =
                """
                {
                  "actor": "some-actor",
                  "path": "some${specialCharacter}path",
                  "operations": ["read", "write"]
                }
                """.trimIndent()

            val violations =
                JsonTestHelper
                    .deserializeAndValidate(json, PermissionsV2Request::class.java)

            MatcherAssert.assertThat(violations.size, equalTo(0))
        }
    }

    @Test
    fun whenPathEndsInSlashStar_shouldBeValid() {
        // language=JSON
        val json =
            """
            {
              "actor": "some-actor",
              "path": "some-path/*",
              "operations": ["read", "write"]
            }
            """.trimIndent()

        val violations =
            JsonTestHelper
                .deserializeAndValidate(json, PermissionsV2Request::class.java)

        MatcherAssert.assertThat(violations.size, equalTo(0))
    }
}
