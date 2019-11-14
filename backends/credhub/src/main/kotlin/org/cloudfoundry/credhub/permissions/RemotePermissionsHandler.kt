package org.cloudfoundry.credhub.permissions

import com.google.protobuf.ProtocolStringList
import io.grpc.Status
import io.grpc.StatusRuntimeException
import java.util.UUID
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.PermissionsResponse
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service

@Service
@Profile("remote")
@Component
class RemotePermissionsHandler(
    private val userContextHolder: UserContextHolder,
    private val client: RemoteBackendClient
) : PermissionsV2Handler {

    override fun getPermissions(guid: UUID): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionsV2View {
        val requester = userContextHolder.userContext.actor
        val operationStrings = permissionsRequest.operations.map { o -> o.operation }.toMutableList()

        val response: PermissionsResponse
        try {
            response = client.putPermissionRequest(guid, permissionsRequest.getPath(), permissionsRequest.actor, operationStrings, requester)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        val responseOperations = mapOperationStringsToOperations(response.operationsList)
        return PermissionsV2View(response.path, responseOperations, response.actor, UUID.fromString(response.uuid))
    }

    override fun patchPermissions(guid: String, operations: List<PermissionOperation>): PermissionsV2View {
        val requester = userContextHolder.userContext.actor
        val operationStrings = operations.map { o -> o.operation }.toMutableList()

        val response: PermissionsResponse
        try {
            response = client.patchPermissionRequest(guid, operationStrings, requester)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        val responseOperations = mapOperationStringsToOperations(response.operationsList)
        return PermissionsV2View(response.path, responseOperations, response.actor, UUID.fromString(response.uuid))
    }

    override fun writePermissions(request: PermissionsV2Request): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun writeV2Permissions(permissionsRequest: PermissionsV2Request): PermissionsV2View {
        val requester = userContextHolder.userContext.actor
        val operationStrings = permissionsRequest.operations.map { o -> o.operation }.toMutableList()

        val response: PermissionsResponse
        try {
            response = client.writePermissionRequest(permissionsRequest.getPath(), permissionsRequest.actor, operationStrings, requester)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        val responseOperations = mapOperationStringsToOperations(response.operationsList)
        return PermissionsV2View(response.path, responseOperations, response.actor, UUID.fromString(response.uuid))
    }

    override fun deletePermissions(guid: String): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findByPathAndActor(path: String, actor: String): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    private fun mapOperationStringsToOperations(operations: ProtocolStringList): MutableList<PermissionOperation> {
        val result = mutableListOf<PermissionOperation>()
        for (o in operations) {
            when (o.toLowerCase()) {
                "read" -> result.add(PermissionOperation.READ)
                "write" -> result.add(PermissionOperation.WRITE)
                "delete" -> result.add(PermissionOperation.DELETE)
                "read_acl" -> result.add(PermissionOperation.READ_ACL)
                "write_acl" -> result.add(PermissionOperation.WRITE_ACL)
            }
        }
        return result
    }

    private fun handleException(e: StatusRuntimeException): Exception {
        if (e.status.code == Status.NOT_FOUND.code) {
            return EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        return RuntimeException("Request failed with status code: ${e.status.code}")
    }
}
