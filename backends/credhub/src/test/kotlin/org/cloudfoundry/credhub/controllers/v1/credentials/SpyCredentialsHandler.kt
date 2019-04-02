package org.cloudfoundry.credhub.controllers.v1.credentials

import org.cloudfoundry.credhub.generate.CredentialsHandler
import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse

class SpyCredentialsHandler : CredentialsHandler {

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
