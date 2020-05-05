package org.cloudfoundry.credhub.data

import com.google.common.collect.Lists
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import java.util.ArrayList
import java.util.HashSet
import java.util.UUID
import kotlin.streams.toList
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.audit.AuditablePermissionData
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.entities.V2Permission
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException
import org.cloudfoundry.credhub.exceptions.PermissionInvalidPathAndActorException
import org.cloudfoundry.credhub.repositories.PermissionRepository
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.services.CredentialDataService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
@SuppressFBWarnings(value = ["NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE"], justification = "Let's refactor this class into kotlin")
class PermissionDataService @Autowired
constructor(
    private val permissionRepository: PermissionRepository,
    private val credentialDataService: CredentialDataService,
    private val auditRecord: CEFAuditRecord
) {

    fun getPermissions(credential: Credential): MutableList<PermissionEntry> {
        return createViewsFromPermissionsFor(credential)
    }

    fun getPermission(guid: UUID): PermissionData? {
        val data = permissionRepository.findByUuid(guid)
        auditRecord.setResource(data)
        return data
    }

    fun savePermissionsWithLogging(permissions: List<PermissionEntry>?): List<PermissionData> {
        val permissionDatas = savePermissions(permissions)

        auditRecord.addAllResources(Lists.newArrayList<AuditablePermissionData>(permissionDatas))

        val requestDetails = V2Permission(permissionDatas[0].path!!,
            permissionDatas[0].actor!!, permissionDatas[0].generateAccessControlOperations(),
            OperationDeviceAction.ADD_PERMISSIONS)
        auditRecord.requestDetails = requestDetails
        return permissionDatas
    }

    fun savePermissions(permissions: List<PermissionEntry>?): List<PermissionData> {
        val result = ArrayList<PermissionData>()
        for (permission in permissions!!) {
            val path = permission.path
            val existingPermissions = permissionRepository.findAllByPath(path)
            result.add(upsertPermissions(path, existingPermissions, permission.actor,
                permission.allowedOperations))
        }

        return result
    }

    fun getAllowedOperations(name: String, actor: String): List<PermissionOperation> {
        val operations = Lists.newArrayList<PermissionOperation>()
        val permissionData = permissionRepository.findByPathAndActor(name, actor)

        if (permissionData != null) {
            if (permissionData.hasReadPermission()) {
                operations.add(PermissionOperation.READ)
            }
            if (permissionData.hasWritePermission()) {
                operations.add(PermissionOperation.WRITE)
            }
            if (permissionData.hasDeletePermission()) {
                operations.add(PermissionOperation.DELETE)
            }
            if (permissionData.hasReadAclPermission()) {
                operations.add(PermissionOperation.READ_ACL)
            }
            if (permissionData.hasWriteAclPermission()) {
                operations.add(PermissionOperation.WRITE_ACL)
            }
        }

        return operations
    }

    fun deletePermissions(name: String, actor: String): Boolean {
        auditRecord.setResource(permissionRepository.findByPathAndActor(name, actor))
        return permissionRepository.deleteByPathAndActor(name, actor) > 0
    }

    fun findAllPathsByActor(actor: String): Set<String> {
        val result = HashSet<String>()

        permissionRepository.findAllPathsForActorWithReadPermission(actor).forEach { i -> result.add(i) }

        return result
    }

    fun hasNoDefinedAccessControl(name: String): Boolean {
        credentialDataService.find(name) ?: return false
        return permissionRepository.findAllByPath(name).isEmpty()
    }

    fun hasPermission(user: String, path: String, requiredPermission: PermissionOperation): Boolean {
        for (permissionData in permissionRepository.findByPathsAndActor(findAllPaths(path), user)) {
            if (permissionData.hasPermission(requiredPermission)) {
                return true
            }
        }
        return false
    }

    private fun upsertPermissions(
        path: String?,
        accessEntries: List<PermissionData>,
        actor: String?,
        operations: List<PermissionOperation>?
    ): PermissionData {
        var entry: PermissionData? = findAccessEntryForActor(accessEntries, actor)

        if (entry == null) {
            entry = PermissionData(path, actor)
        }

        entry.enableOperations(operations)
        permissionRepository.saveAndFlush(entry)

        return entry
    }

    private fun findAllPaths(path: String): List<String> {
        val result = ArrayList<String>()
        result.add(path)

        val pathSeparator = '/'

        for (i in 0 until path.length) {
            if (path[i] == pathSeparator) {
                result.add(path.substring(0, i + 1) + "*")
            }
        }

        return result
    }

    private fun createViewFor(data: PermissionData?): PermissionEntry? {
        if (data == null) {
            return null
        }
        val entry = PermissionEntry()
        val operations = data.generateAccessControlOperations()
        entry.allowedOperations = operations
        entry.path = data.path
        entry.actor = data.actor
        return entry
    }

    private fun createViewsFromPermissionsFor(credential: Credential): MutableList<PermissionEntry> {
        val data = permissionRepository.findAllByPath(credential.name)
        auditRecord.addAllResources(Lists.newArrayList<AuditablePermissionData>(data))

        return data.stream().map<PermissionEntry> { this.createViewFor(it) }.toList().toMutableList()
    }

    private fun findAccessEntryForActor(
        accessEntries: List<PermissionData>,
        actor: String?
    ): PermissionData? {
        val temp = accessEntries.stream()
            .filter { permissionData -> permissionData.actor == actor }
            .findFirst()
        return temp.orElse(null)
    }

    fun permissionExists(user: String, path: String): Boolean {
        return permissionRepository.findByPathAndActor(path, user) != null
    }

    fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionData {
        var existingPermissionData: PermissionData? = null

        try {
            existingPermissionData = permissionRepository.findByUuid(UUID.fromString(guid))
        } catch (e: IllegalArgumentException) {
            if (e.message != null && e.message!!.startsWith("Invalid UUID string:")) {
                throw PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST)
            }
        }

        if (existingPermissionData == null) {
            throw PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST)
        }

        if (!(existingPermissionData.path == permissionsRequest.getPath() && existingPermissionData.actor == permissionsRequest.actor)) {
            throw PermissionInvalidPathAndActorException(ErrorMessages.Permissions.WRONG_PATH_AND_ACTOR)
        }

        val permissionData = PermissionData(permissionsRequest.getPath(),
            permissionsRequest.actor, permissionsRequest.operations)

        permissionData.uuid = existingPermissionData.uuid
        permissionRepository.save(permissionData)
        auditRecord.setResource(permissionData)

        val requestDetails = V2Permission(permissionData.path!!,
            permissionData.actor!!, permissionData.generateAccessControlOperations(),
            OperationDeviceAction.PUT_PERMISSIONS)
        auditRecord.requestDetails = requestDetails

        return permissionData
    }

    fun patchPermissions(guid: String, operations: MutableList<PermissionOperation>?): PermissionData {
        var existingPermissionData: PermissionData? = null

        existingPermissionData = permissionRepository.findByUuid(UUID.fromString(guid))

        if (existingPermissionData == null) {
            throw PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST)
        }

        val patchedRecord = PermissionData(existingPermissionData.path,
            existingPermissionData.actor, operations)
        patchedRecord.uuid = existingPermissionData.uuid

        permissionRepository.save(patchedRecord)
        auditRecord.setResource(patchedRecord)

        val requestDetails = V2Permission(patchedRecord.path!!,
            patchedRecord.actor!!, patchedRecord.generateAccessControlOperations(),
            OperationDeviceAction.PATCH_PERMISSIONS)
        auditRecord.requestDetails = requestDetails

        return patchedRecord
    }

    fun saveV2Permissions(permissionsRequest: PermissionsV2Request): PermissionData {
        val existingPermissionData = permissionRepository.findByPathAndActor(permissionsRequest.getPath(),
            permissionsRequest.actor)

        if (existingPermissionData != null) {
            throw PermissionAlreadyExistsException(ErrorMessages.Permissions.ALREADY_EXISTS)
        }

        val record = PermissionData()
        record.path = permissionsRequest.getPath()
        record.actor = permissionsRequest.actor
        record.enableOperations(permissionsRequest.operations)

        permissionRepository.save(record)

        auditRecord.setResource(record)

        val requestDetails = V2Permission(record.path!!, record.actor!!,
            record.generateAccessControlOperations(), OperationDeviceAction.ADD_PERMISSIONS)
        auditRecord.requestDetails = requestDetails

        return record
    }

    fun deletePermissions(guid: UUID): PermissionData {
        val existingPermission = permissionRepository.findByUuid(guid)
        permissionRepository.delete(existingPermission!!)

        val requestDetails = V2Permission(existingPermission.path!!,
            existingPermission.actor!!, existingPermission.generateAccessControlOperations(),
            OperationDeviceAction.DELETE_PERMISSIONS)
        auditRecord.requestDetails = requestDetails
        auditRecord.setResource(existingPermission)

        return existingPermission
    }

    fun findByPathAndActor(path: String, actor: String): PermissionData? {
        return permissionRepository.findByPathAndActor(path, actor)
    }
}
