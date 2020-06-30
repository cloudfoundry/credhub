package org.cloudfoundry.credhub.requests

import com.google.common.collect.Lists.newArrayList
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.deserialize
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.hasViolationWithMessage
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.serialize
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.validate
import org.hamcrest.CoreMatchers.allOf
import org.hamcrest.MatcherAssert
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.hasProperty
import org.hamcrest.core.IsCollectionContaining.hasItems
import org.hamcrest.core.IsEqual.equalTo
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class PermissionsRequestTest {
    @Test
    fun validation_allowsGoodJson() {
        val entryList = newArrayList(
            PermissionEntry("someone", "test-path", newArrayList(PermissionOperation.READ))
        )
        val original = PermissionsRequest("test-name", entryList)
        val json = serialize(original)!!
        val actual = deserialize<PermissionsRequest>(json, PermissionsRequest::class.java)

        assertThat(actual.credentialName, equalTo("/test-name"))
        assertThat(
            actual.permissions,
            contains(
                allOf(
                    hasProperty("actor", equalTo("someone")),
                    hasProperty<PermissionEntry>("allowedOperations", hasItems(PermissionOperation.READ))
                )
            )
        )
    }

    @Test
    fun validation_ensuresCredentialNameIsNotNull() {
        val entryList = newArrayList(
            PermissionEntry("someone", "test-path", newArrayList(PermissionOperation.READ))
        )
        val original = PermissionsRequest(null, entryList)
        val violations = validate(original)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(violations, Matchers.contains(hasViolationWithMessage(ErrorMessages.MISSING_NAME)))
    }

    @Test
    fun validation_ensuresCredentialNameIsNotEmpty() {
        val entryList = newArrayList(
            PermissionEntry("someone", "test-path", newArrayList(PermissionOperation.READ))
        )
        val original = PermissionsRequest("", entryList)
        val violations = validate(original)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(violations, Matchers.contains(hasViolationWithMessage(ErrorMessages.MISSING_NAME)))
    }

    @Test
    fun validation_ensuresOperationsIsNotNull() {
        val original = PermissionsRequest("foo", null)
        val violations = validate(original)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(violations, Matchers.contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACES)))
    }

    @Test
    fun validation_ensuresOperationsIsNotEmpty() {
        val original = PermissionsRequest("foo", newArrayList())
        val violations = validate(original)

        assertThat(violations.size, equalTo(1))
        MatcherAssert.assertThat(violations, Matchers.contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACES)))
    }
}
