package org.cloudfoundry.credhub.handlers

import io.grpc.Status
import io.grpc.StatusRuntimeException
import org.assertj.core.api.Assertions
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.permissions.RemotePermissionsHandler
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.PermissionsResponse
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.Mockito
import org.mockito.Mockito.`when`
import java.util.UUID

@RunWith(JUnit4::class)
class RemotePermissionsHandlerTest {

    private val CREDENTIAL_NAME = "/test/credential"
    private val USER = "test-user"
    private val ACTOR = "test-actor"

    private lateinit var subject: RemotePermissionsHandler
    private var client = Mockito.mock<RemoteBackendClient>(RemoteBackendClient::class.java)!!
    private val userContextHolder = Mockito.mock<UserContextHolder>(UserContextHolder::class.java)!!

    @Before
    fun beforeEach() {
        subject = RemotePermissionsHandler(userContextHolder, client)

        val userContext = Mockito.mock(UserContext::class.java)
        `when`(userContext.actor).thenReturn(USER)
        `when`(userContextHolder.userContext).thenReturn(userContext)
    }

    @Test
    fun writeV2Permissions_whenUserHasWriteACL_returnsCorrectResponse() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()
        val uuid = UUID.randomUUID()

        val request = PermissionsV2Request()
        request.actor = ACTOR
        request.setPath(CREDENTIAL_NAME)
        request.operations = operations

        val response = PermissionsResponse.newBuilder().setActor(ACTOR).setPath(CREDENTIAL_NAME).setUuid(uuid.toString())
            .addAllOperations(operationStrings).build()

        `when`(client.writePermissionRequest(CREDENTIAL_NAME, ACTOR, operationStrings, USER))
            .thenReturn(response)

        val result = subject.writeV2Permissions(request)
        assertEquals(result.actor, ACTOR)
        assertEquals(result.path, CREDENTIAL_NAME)
        assertEquals(result.operations, operations)
        assertEquals(result.uuid, uuid)
    }

    @Test
    fun writeV2Permissions_whenUserDoesNotHaveACL_returnsException() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()

        val request = PermissionsV2Request()
        request.actor = ACTOR
        request.setPath(CREDENTIAL_NAME)
        request.operations = operations

        val exception = StatusRuntimeException(Status.NOT_FOUND)

        `when`(client.writePermissionRequest(CREDENTIAL_NAME, ACTOR, operationStrings, USER))
            .thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.writeV2Permissions(request)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun patchPermissions_whenUserHasWriteACL_returnsCorrectResponse() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()
        val uuid = UUID.randomUUID()

        val response = PermissionsResponse.newBuilder().setActor(ACTOR).setPath(CREDENTIAL_NAME).setUuid(uuid.toString())
            .addAllOperations(operationStrings).build()

        `when`(client.patchPermissionRequest(uuid.toString(), operationStrings, USER))
            .thenReturn(response)

        val result = subject.patchPermissions(uuid.toString(), operations)
        assertEquals(result.actor, ACTOR)
        assertEquals(result.path, CREDENTIAL_NAME)
        assertEquals(result.operations, operations)
        assertEquals(result.uuid, uuid)
    }

    @Test
    fun patchPermissions_whenUserDoesNotHaveACL_returnsException() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()
        val uuid = UUID.randomUUID()

        val exception = StatusRuntimeException(Status.NOT_FOUND)

        `when`(client.patchPermissionRequest(uuid.toString(), operationStrings, USER))
            .thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.patchPermissions(uuid.toString(), operations)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun putPermissions_whenUserHasWriteACL_returnsCorrectResponse() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()
        val uuid = UUID.randomUUID()

        val request = PermissionsV2Request()
        request.actor = ACTOR
        request.setPath(CREDENTIAL_NAME)
        request.operations = operations

        val response = PermissionsResponse.newBuilder().setActor(ACTOR).setPath(CREDENTIAL_NAME).setUuid(uuid.toString())
            .addAllOperations(operationStrings).build()

        `when`(client.putPermissionRequest(uuid.toString(), CREDENTIAL_NAME, ACTOR, operationStrings, USER))
            .thenReturn(response)

        val result = subject.putPermissions(uuid.toString(), request)
        assertEquals(result.actor, ACTOR)
        assertEquals(result.path, CREDENTIAL_NAME)
        assertEquals(result.operations, operations)
        assertEquals(result.uuid, uuid)
    }

    @Test
    fun putPermissions_whenUserDoesNotHaveACL_returnsException() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()
        val uuid = UUID.randomUUID()

        val request = PermissionsV2Request()
        request.actor = ACTOR
        request.setPath(CREDENTIAL_NAME)
        request.operations = operations

        val exception = StatusRuntimeException(Status.NOT_FOUND)

        `when`(client.putPermissionRequest(uuid.toString(), CREDENTIAL_NAME, ACTOR, operationStrings, USER))
            .thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.putPermissions(uuid.toString(), request)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findByPathAndActor_whenUserDoesHaveReadACL_returnsCorrectResponse() {
        val operations = listOf(PermissionOperation.READ, PermissionOperation.WRITE)
        val operationStrings = operations.map { o -> o.operation }.toMutableList()
        val uuid = UUID.randomUUID()

        val response = PermissionsResponse.newBuilder().setActor(ACTOR).setPath(CREDENTIAL_NAME).setUuid(uuid.toString())
            .addAllOperations(operationStrings).build()

        `when`(client.findPermissionByPathAndActor(CREDENTIAL_NAME, ACTOR, USER))
            .thenReturn(response)

        val result = subject.findByPathAndActor(CREDENTIAL_NAME, ACTOR)

        assertEquals(result.actor, ACTOR)
        assertEquals(result.path, CREDENTIAL_NAME)
        assertEquals(result.operations, operations)
        assertEquals(result.uuid, uuid)
    }

    @Test
    fun findByPathAndActor_whenUserDoesNotHaveReadACL_returnsException() {
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.findPermissionByPathAndActor(CREDENTIAL_NAME, ACTOR, USER))
            .thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.findByPathAndActor(CREDENTIAL_NAME, ACTOR)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }
}
