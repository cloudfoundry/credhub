package org.cloudfoundry.credhub.services

import com.google.common.collect.Lists.newArrayList
import junit.framework.TestCase.assertFalse
import org.apache.commons.lang3.RandomStringUtils
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.READ_ACL
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.entities.V2Permission
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.data.PermissionDataService
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.CoreMatchers.allOf
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.containsInAnyOrder
import org.hamcrest.Matchers.hasItem
import org.hamcrest.Matchers.hasProperty
import org.hamcrest.Matchers.not
import org.hamcrest.collection.IsCollectionWithSize.hasSize
import org.hamcrest.core.Is.`is`
import org.hamcrest.core.IsCollectionContaining.hasItems
import org.hamcrest.core.IsEqual.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.transaction.annotation.Transactional

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
class PermissionDataServiceTest {

    @Autowired
    private val subject: PermissionDataService? = null

    @Autowired
    private val credentialDataService: CredentialDataService? = null

    @Autowired
    private val auditRecord: CEFAuditRecord? = null

    private var aces: List<PermissionEntry>? = null
    private var credential: Credential? = null

    @Before
    fun beforeEach() {
        seedDatabase()
    }

    @Test
    fun getAccessControlList_givenExistingCredentialName_returnsAcl() {
        val accessControlEntries = subject!!.getPermissions(credential!!)

        assertThat<List<PermissionEntry>>(accessControlEntries, hasSize(3))

        assertThat<List<PermissionEntry>>(
            accessControlEntries,
            containsInAnyOrder(
                allOf(
                    hasProperty("actor", equalTo(LUKE)),
                    hasProperty("allowedOperations", hasItems(WRITE))
                ),
                allOf(
                    hasProperty("actor", equalTo(LEIA)),
                    hasProperty("allowedOperations", hasItems(READ))
                ),
                allOf(
                    hasProperty("actor", equalTo(HAN_SOLO)),
                    hasProperty(
                        "allowedOperations",
                        hasItems(READ_ACL)
                    )
                )
            )
        )
    }

    @Test
    fun findByPathAndActor_givenAnActorAndPath_returnsPermissionData() {
        val actualPermission = subject!!.findByPathAndActor(CREDENTIAL_NAME, LUKE)
        val expectedPermission = PermissionData(CREDENTIAL_NAME, LUKE, newArrayList(WRITE, DELETE))
        expectedPermission.uuid = actualPermission!!.uuid

        assertThat(
            actualPermission,
            equalTo(expectedPermission)
        )
    }

    @Test
    fun getAllowedOperations_whenTheCredentialExists_andTheActorHasPermissions_returnsListOfActivePermissions() {
        assertThat(
            subject!!.getAllowedOperations(CREDENTIAL_NAME, LUKE),
            containsInAnyOrder(
                WRITE,
                DELETE
            )
        )
    }

    @Test
    fun getAllowedOperations_whenTheCredentialExists_andTheActorHasNoPermissions_returnsEmptyList() {
        assertThat(subject!!.getAllowedOperations(CREDENTIAL_NAME, DARTH).size, equalTo(0))
    }

    @Test
    fun getAllowedOperations_whenTheCredentialDoesNotExist_returnsEmptyList() {
        assertThat(subject!!.getAllowedOperations("/unicorn", LEIA).size, equalTo(0))
    }

    @Test
    fun getAccessControlList_whenGivenNonExistentCredentialName_throwsException() {
        try {
            subject!!.getPermissions(Credential(CREDENTIAL_NAME_DOES_NOT_EXIST))
        } catch (enfe: EntryNotFoundException) {
            assertThat(enfe.message, Matchers.equalTo(ErrorMessages.RESOURCE_NOT_FOUND))
        }
    }

    @Test
    fun setAccessControlEntries_whenGivenAnExistingAce_returnsTheAcl() {
        aces = listOf(PermissionEntry(LUKE, CREDENTIAL_NAME, listOf(READ)))

        subject!!.savePermissionsWithLogging(aces)

        val response = subject.getPermissions(credential!!)

        assertThat<List<PermissionEntry>>(
            response,
            containsInAnyOrder(
                allOf(
                    hasProperty("actor", equalTo(LUKE)),
                    hasProperty(
                        "allowedOperations",
                        hasItems(READ, WRITE)
                    )
                ),
                allOf(
                    hasProperty("actor", equalTo(LEIA)),
                    hasProperty("allowedOperations", hasItems(READ))
                ),
                allOf(
                    hasProperty("actor", equalTo(HAN_SOLO)),
                    hasProperty(
                        "allowedOperations",
                        hasItems(READ_ACL)
                    )
                )
            )
        )
    }

    @Test
    fun setAccessControlEntries_whenGivenANewAce_returnsTheAcl() {
        val valueCredentialData2 = ValueCredentialVersionData("lightsaber2")
        val credential2 = valueCredentialData2.credential

        credentialDataService!!.save(credential2)
        aces = listOf(PermissionEntry(LUKE, credential2?.name, listOf<PermissionOperation>(READ)))

        subject!!.savePermissionsWithLogging(aces)

        val response = subject.getPermissions(credential2!!)

        val permissionEntry = response[0]

        assertThat<List<PermissionEntry>>(response, hasSize(1))
        assertThat(permissionEntry.actor, equalTo(LUKE))
        assertThat(permissionEntry.allowedOperations, hasSize(1))
        assertThat(permissionEntry.allowedOperations, hasItem(READ))
    }

    @Test
    fun deleteAccessControlEntry_whenGivenExistingCredentialAndActor_deletesTheAce() {
        subject!!.deletePermissions(CREDENTIAL_NAME, LUKE)

        val accessControlList = subject
            .getPermissions(credential!!)

        assertThat<List<PermissionEntry>>(accessControlList, hasSize(2))

        assertThat<List<PermissionEntry>>(
            accessControlList,
            not(contains(hasProperty("actor", equalTo(LUKE))))
        )
    }

    @Test
    fun deleteAccessControlEntry_whenNonExistentResource_returnsFalse() {
        val deleted = subject!!.deletePermissions("/some-thing-that-is-not-here", LUKE)
        assertFalse(deleted)
    }

    @Test
    fun deleteAccessControlEntry_whenNonExistentAce_returnsFalse() {
        val deleted = subject!!.deletePermissions(CREDENTIAL_NAME, DARTH)
        assertFalse(deleted)
    }

    @Test
    fun deletePermissions_addsToAuditRecord() {
        subject!!.deletePermissions(CREDENTIAL_NAME, LUKE)
        assertThat(auditRecord!!.resourceName, `is`(CREDENTIAL_NAME))
    }

    @Test
    fun patchPermissions_addsToAuditRecord() {
        val operations = ArrayList<PermissionOperation>()
        val pathName = randomCredentialPath()
        operations.add(PermissionOperation.READ)

        val permission = PermissionsV2Request()
        permission.setPath(pathName)
        permission.actor = LUKE
        permission.operations = operations

        val permissionData = subject!!.saveV2Permissions(permission)
        assertThat(permissionData.uuid, notNullValue())

        val newOperations = ArrayList<PermissionOperation>()
        newOperations.add(PermissionOperation.WRITE)

        subject.patchPermissions(permissionData.uuid!!.toString(), newOperations)

        assertThat(auditRecord!!.resourceUUID, `is`(permissionData.uuid!!.toString()))
        val requestDetails = auditRecord.requestDetails as V2Permission
        assertThat(requestDetails.operations, containsInAnyOrder(PermissionOperation.WRITE))
        assertThat(requestDetails.operation(), `is`(OperationDeviceAction.PATCH_PERMISSIONS))
    }

    @Test
    fun putPermissions_addsToAuditRecord() {
        val request = PermissionsV2Request()

        val permissions = ArrayList<PermissionEntry>()
        val operations = ArrayList<PermissionOperation>()
        operations.add(PermissionOperation.READ)

        val permissionEntry = PermissionEntry()
        permissionEntry.path = CREDENTIAL_NAME
        permissionEntry.actor = LUKE
        permissionEntry.allowedOperations = operations

        permissions.add(permissionEntry)

        val permissionData = subject!!.savePermissionsWithLogging(permissions)[0]

        val newOperations = ArrayList<PermissionOperation>()
        newOperations.add(PermissionOperation.WRITE)

        request.setPath(CREDENTIAL_NAME)
        request.actor = LUKE
        request.operations = newOperations

        subject.putPermissions(permissionData.uuid!!.toString(), request)

        assertThat(auditRecord!!.resourceName, `is`(CREDENTIAL_NAME))
        val requestDetails = auditRecord.requestDetails as V2Permission
        assertThat(requestDetails.path, `is`(CREDENTIAL_NAME))
        assertThat(requestDetails.actor, `is`(LUKE))
        assertThat(requestDetails.operations, contains(PermissionOperation.WRITE))
        assertThat(requestDetails.operation(), `is`(OperationDeviceAction.PUT_PERMISSIONS))
    }

    @Test
    fun savePermissions_addsToAuditRecord() {
        val permissions = ArrayList<PermissionEntry>()
        val operations = ArrayList<PermissionOperation>()
        operations.add(PermissionOperation.READ)

        val permissionEntry = PermissionEntry()
        permissionEntry.path = CREDENTIAL_NAME
        permissionEntry.actor = LUKE
        permissionEntry.allowedOperations = operations

        permissions.add(permissionEntry)

        subject!!.savePermissionsWithLogging(permissions)

        val resources = auditRecord!!.resourceList

        assertThat(resources?.get(resources.size - 1)?.resourceName, `is`(CREDENTIAL_NAME))
        val requestDetails = auditRecord.requestDetails as V2Permission
        assertThat(requestDetails.path, `is`(CREDENTIAL_NAME))
        assertThat(requestDetails.actor, `is`(LUKE))
    }

    @Test
    fun saveV2Permissions_addsToAuditRecord() {
        val path = randomCredentialPath()
        val permission = PermissionsV2Request()
        val operations = ArrayList<PermissionOperation>()
        operations.add(PermissionOperation.READ)

        permission.setPath(path)
        permission.actor = LUKE
        permission.operations = operations

        subject!!.saveV2Permissions(permission)

        assertThat(auditRecord!!.resourceName, `is`(path))
        val requestDetails = auditRecord.requestDetails as V2Permission
        assertThat(requestDetails.path, `is`(path))
        assertThat(requestDetails.actor, `is`(LUKE))
        assertThat(requestDetails.operation(), `is`(OperationDeviceAction.ADD_PERMISSIONS))
    }

    @Test
    fun deleteV2Permissions_addsToAuditRecord() {
        val request = PermissionsV2Request()

        val operations = mutableListOf(PermissionOperation.READ)

        val credentialName = randomCredentialPath()
        request.setPath(credentialName)
        request.actor = LUKE
        request.operations = operations

        val permissionData = subject!!.saveV2Permissions(request)

        subject.deletePermissions(permissionData.uuid!!)

        assertThat(auditRecord!!.resourceName, `is`(credentialName))
        val requestDetails = auditRecord.requestDetails as V2Permission
        assertThat(requestDetails.path, `is`(credentialName))
        assertThat(requestDetails.actor, `is`(LUKE))
        assertThat(requestDetails.operations, contains(PermissionOperation.READ))
        assertThat(requestDetails.operation(), `is`(OperationDeviceAction.DELETE_PERMISSIONS))
    }

    @Test
    fun getPermissionsByUUID_addsToAuditRecord() {
        val guid = subject!!.savePermissions(listOf(PermissionEntry(LUKE, CREDENTIAL_NAME, newArrayList(WRITE, DELETE))))[0].uuid
        subject.getPermission(guid!!)
        assertThat(auditRecord!!.resourceName, `is`(CREDENTIAL_NAME))
    }

    @Test
    fun hasAclReadPermission_whenActorHasAclRead_returnsTrue() {
        assertThat(
            subject!!.hasPermission(HAN_SOLO, CREDENTIAL_NAME, READ_ACL),
            `is`(true)
        )
    }

    @Test
    fun hasAclReadPermission_whenActorHasReadButNotReadAcl_returnsFalse() {
        assertThat(
            subject!!.hasPermission(LUKE, CREDENTIAL_NAME, READ),
            `is`(false)
        )
    }

    @Test
    fun hasAclReadPermission_whenActorHasNoPermissions_returnsFalse() {
        assertThat(
            subject!!.hasPermission(CHEWIE, CREDENTIAL_NAME, READ),
            `is`(false)
        )
    }

    @Test
    fun hasAclReadPermission_whenCredentialDoesNotExist_returnsFalse() {
        assertThat(
            subject!!.hasPermission(LUKE, CREDENTIAL_NAME_DOES_NOT_EXIST, READ),
            `is`(false)
        )
    }

    @Test
    fun hasAclWritePermission_whenActorHasAclWrite_returnsTrue() {
        assertThat(
            subject!!.hasPermission(HAN_SOLO, CREDENTIAL_NAME, WRITE_ACL),
            `is`(true)
        )
    }

    @Test
    fun hasAclWritePermission_whenActorHasWriteButNotWriteAcl_returnsFalse() {
        assertThat(
            subject!!.hasPermission(LUKE, CREDENTIAL_NAME, WRITE_ACL),
            `is`(false)
        )
    }

    @Test
    fun hasAclWritePermission_whenActorHasNoPermissions_returnsFalse() {
        assertThat(
            subject!!.hasPermission(CHEWIE, CREDENTIAL_NAME, WRITE_ACL),
            `is`(false)
        )
    }

    @Test
    fun hasAclWritePermission_whenCredentialDoesNotExist_returnsFalse() {
        assertThat(
            subject!!.hasPermission(LUKE, CREDENTIAL_NAME_DOES_NOT_EXIST, WRITE_ACL),
            `is`(false)
        )
    }

    @Test
    fun hasReadPermission_whenActorHasRead_returnsTrue() {
        assertThat(
            subject!!.hasPermission(LEIA, CREDENTIAL_NAME, READ),
            `is`(true)
        )
    }

    @Test
    fun hasReadPermission_givenNameWithoutLeadingSlashAndHasRead_returnsTrue() {
        assertThat(
            subject!!.hasPermission(LEIA, CREDENTIAL_NAME, READ),
            `is`(true)
        )
    }

    @Test
    fun hasReadPermission_whenActorHasWriteButNotRead_returnsFalse() {
        assertThat(
            subject!!.hasPermission(LUKE, CREDENTIAL_NAME, READ),
            `is`(false)
        )
    }

    @Test
    fun hasReadPermission_whenActorHasNoPermissions_returnsFalse() {
        assertThat(
            subject!!.hasPermission(CHEWIE, CREDENTIAL_NAME, READ),
            `is`(false)
        )
    }

    @Test
    fun hasCredentialWritePermission_whenActorHasWritePermission_returnsTrue() {
        assertThat(subject!!.hasPermission(LUKE, CREDENTIAL_NAME, WRITE), `is`(true))
    }

    @Test
    fun hasCredentialWritePermission_whenActorOnlyHasOtherPermissions_returnsFalse() {
        assertThat(subject!!.hasPermission(LEIA, CREDENTIAL_NAME, WRITE), `is`(false))
    }

    @Test
    fun hasCredentialWritePermission_whenActorHasNoPermissions_returnsFalse() {
        assertThat(subject!!.hasPermission(DARTH, CREDENTIAL_NAME, WRITE), `is`(false))
    }

    @Test
    fun hasCredentialDeletePermission_whenActorHasDeletePermission_returnsTrue() {
        assertThat(subject!!.hasPermission(LUKE, CREDENTIAL_NAME, DELETE), `is`(true))
    }

    @Test
    fun hasCredentialDeletePermission_whenActorOnlyHasOtherPermissions_returnsFalse() {
        assertThat(subject!!.hasPermission(LEIA, CREDENTIAL_NAME, DELETE), `is`(false))
    }

    @Test
    fun hasCredentialDeletePermission_whenActorHasNoPermissions_returnsFalse() {
        assertThat(subject!!.hasPermission(DARTH, CREDENTIAL_NAME, DELETE), `is`(false))
    }

    @Test
    fun hasReadPermission_whenCredentialDoesNotExist_returnsFalse() {
        assertThat(
            subject!!.hasPermission(LUKE, CREDENTIAL_NAME_DOES_NOT_EXIST, READ),
            `is`(false)
        )
    }

    @Test
    fun hasNoPermissions_whenCredentialHasPermissions_returnsFalse() {
        assertThat(subject!!.hasNoDefinedAccessControl(CREDENTIAL_NAME), `is`(false))
    }

    @Test
    fun hasNoPermissions_whenCredentialDoesNotExist_returnsFalse() {
        assertThat(subject!!.hasNoDefinedAccessControl(CREDENTIAL_NAME_DOES_NOT_EXIST), `is`(false))
    }

    @Test
    fun hasNoPermissions_whenCredentialHasNoPermissions_returnsTrue() {
        assertThat(subject!!.hasNoDefinedAccessControl(NO_ACCESS_CREDENTIAL_NAME), `is`(true))
    }

    private fun seedDatabase() {
        val valueCredentialData = ValueCredentialVersionData(CREDENTIAL_NAME)
        credential = valueCredentialData.credential
        this.credential = credentialDataService!!.save(this.credential)

        val noAccessValueCredentialData = ValueCredentialVersionData(NO_ACCESS_CREDENTIAL_NAME)
        val noAccessValueCredential = noAccessValueCredentialData.credential
        credentialDataService.save(noAccessValueCredential)

        subject!!.savePermissionsWithLogging(listOf(PermissionEntry(LUKE, CREDENTIAL_NAME, newArrayList(WRITE, DELETE))))
        subject.savePermissionsWithLogging(listOf(PermissionEntry(LEIA, CREDENTIAL_NAME, listOf(READ))))
        subject.savePermissionsWithLogging(listOf(PermissionEntry(HAN_SOLO, CREDENTIAL_NAME, newArrayList(READ_ACL, WRITE_ACL))))
    }

    private fun randomCredentialPath(): String {
        return "/" + RandomStringUtils.randomAlphanumeric(50)
    }

    companion object {
        private val CREDENTIAL_NAME = "/lightsaber"
        private val CREDENTIAL_NAME_DOES_NOT_EXIST = "/this/credential/does/not/exist"

        private val LUKE = "Luke"
        private val LEIA = "Leia"
        private val HAN_SOLO = "HansSolo"
        private val DARTH = "Darth"
        private val CHEWIE = "Chewie"
        private val NO_ACCESS_CREDENTIAL_NAME = "Alderaan"
    }
}
