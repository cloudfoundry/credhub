package org.cloudfoundry.credhub.requests

import jakarta.validation.ConstraintViolation
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.deserializeAndValidate
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.hasViolationWithMessage
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.USER_A_ACTOR_ID
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.USER_A_PATH
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.contains
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.exc.InvalidFormatException
import java.io.IOException

class PermissionEntryTest {
    @Test
    @Throws(IOException::class)
    fun validation_allowsGoodJson() {
        val json = ("{ \n\"actor\": \"$USER_A_ACTOR_ID\",\n\"operations\": [\"read\"],\n\"path\": \"$USER_A_PATH\"}")
        val om = ObjectMapper()
        val permissionEntry = om.readValue(json, PermissionEntry::class.java)
        assertThat(permissionEntry.actor, equalTo(USER_A_ACTOR_ID))
        assertThat(permissionEntry.path, equalTo(USER_A_PATH))
    }

    @Test
    fun validation_ensuresPresenceOfActor() {
        val json = ("{ \n\"operations\": [\"read\"],\n\"path\": \"$USER_A_PATH\"}")
        val constraintViolations = deserializeAndValidate<PermissionEntry>(json, PermissionEntry::class.java)
        assertThat(
            constraintViolations,
            contains<ConstraintViolation<PermissionEntry>>(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACTOR)),
        )
    }

    @Test
    fun validation_ensuresActorIsNotEmpty() {
        val json = ("{ \n\"actor\":\"\",\"operations\": [\"read\"],\n\"path\": \"$USER_A_PATH\"}")
        val constraintViolations = deserializeAndValidate<PermissionEntry>(json, PermissionEntry::class.java)
        assertThat(
            constraintViolations,
            contains<ConstraintViolation<PermissionEntry>>(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACTOR)),
        )
    }

    @Test
    fun validation_ensuresOperationsIsNotNull() {
        val json = ("{\"actor\": \"$USER_A_ACTOR_ID\",\"path\": \"$USER_A_PATH\"}")
        val constraintViolations = deserializeAndValidate<PermissionEntry>(json, PermissionEntry::class.java)
        assertThat(
            constraintViolations,
            contains<ConstraintViolation<PermissionEntry>>(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_OPERATIONS)),
        )
    }

    @Test
    fun validation_ensuresOperationsIsNotEmpty() {
        val json = ("{\"actor\": \"$USER_A_ACTOR_ID\",\"operations\": [],\"path\": \"$USER_A_PATH\"}")
        val constraintViolations = deserializeAndValidate<PermissionEntry>(json, PermissionEntry::class.java)
        assertThat(
            constraintViolations,
            contains<ConstraintViolation<PermissionEntry>>(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_OPERATIONS)),
        )
    }

    @Test
    fun validation_ensuresOperationsAreAllValid() {
        val json = ("{ \n\"actor\": \"$USER_A_ACTOR_ID\",\n\"operations\": [\"foo\", \"read\"],\n\"path\": \"$USER_A_PATH\"}")
        assertThrows<InvalidFormatException> {
            deserializeAndValidate<PermissionEntry>(json, PermissionEntry::class.java)
        }
    }

    @Test
    fun validation_ensuresPathIsNotEmpty() {
        val json = ("{\"actor\": \"$USER_A_ACTOR_ID\",\"operations\": [\"read\"]}")
        val constraintViolations = deserializeAndValidate<PermissionEntry>(json, PermissionEntry::class.java)
        assertThat(
            constraintViolations,
            contains<ConstraintViolation<PermissionEntry>>(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_PATH)),
        )
    }
}
