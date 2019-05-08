package org.cloudfoundry.credhub.controllers.v1.credentials

import org.cloudfoundry.credhub.credentials.CredentialsHandler
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse
import org.cloudfoundry.credhub.views.FindCredentialResult

class SpyCredentialsHandler : CredentialsHandler {
    lateinit var findStartingWithPath__returns_findCredentialResultList: List<FindCredentialResult>
    lateinit var findStartingWithPath__calledWith_path: String
    lateinit var findStartingWithPath__calledWith_expiresWithinDays: String
    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        findStartingWithPath__calledWith_path = path
        findStartingWithPath__calledWith_expiresWithinDays = expiresWithinDays

        return findStartingWithPath__returns_findCredentialResultList
    }

    lateinit var findContainingName__calledWith_name: String
    lateinit var findContainingName__calledWith_expiresWithinDays: String
    lateinit var findContainingName__returns_findCredentialResultList: List<FindCredentialResult>
    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        findContainingName__calledWith_name = name
        findContainingName__calledWith_expiresWithinDays = expiresWithinDays

        return findContainingName__returns_findCredentialResultList
    }

    lateinit var generateCredential__calledWith_generateRequest: BaseCredentialGenerateRequest
    lateinit var generateCredential__returns_credentialView: CredentialView
    override fun generateCredential(generateRequest: BaseCredentialGenerateRequest): CredentialView {
        generateCredential__calledWith_generateRequest = generateRequest
        return generateCredential__returns_credentialView
    }

    lateinit var setCredential__calledWith_setRequest: BaseCredentialSetRequest<*>
    lateinit var setCredential__returns_credentialView: CredentialView
    override fun setCredential(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        setCredential__calledWith_setRequest = setRequest
        return setCredential__returns_credentialView
    }

    lateinit var deleteCredential__calledWith_credentialName: String
    override fun deleteCredential(credentialName: String) {
        deleteCredential__calledWith_credentialName = credentialName
    }

    override fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getAllCredentialVersions(credentialName: String): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var getCurrentCredentialVersions__calledWith_credentialName: String
    lateinit var getCurrentCredentialVersions__returns_dataResponse: DataResponse
    override fun getCurrentCredentialVersions(credentialName: String): DataResponse {
        getCurrentCredentialVersions__calledWith_credentialName = credentialName

        return getCurrentCredentialVersions__returns_dataResponse
    }

    lateinit var getCredentialVersionByUUID__calledWith_credentialUUID: String
    lateinit var getCredentialVersionByUUID__returns_credentialView: CredentialView
    override fun getCredentialVersionByUUID(credentialUUID: String): CredentialView {
        getCredentialVersionByUUID__calledWith_credentialUUID = credentialUUID
        return getCredentialVersionByUUID__returns_credentialView
    }
}
