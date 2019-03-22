package org.cloudfoundry.credhub.testdoubles

import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse

class SpyCredentialsHandler : CredentialsHandler {

    lateinit var deleteCredential_calledWithCredentialName: String
    override fun deleteCredential(credentialName: String) {
        deleteCredential_calledWithCredentialName = credentialName
    }

    override fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getAllCredentialVersions(credentialName: String): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var getCurrentCredentialVersions_calledWithCredentialName: String
    lateinit var getCurrentCredentialVersions_returns: DataResponse
    override fun getCurrentCredentialVersions(credentialName: String): DataResponse {
        getCurrentCredentialVersions_calledWithCredentialName = credentialName

        return getCurrentCredentialVersions_returns
    }

    lateinit var getCredentialVersionByUUID_calledWithCredentialUUID: String
    lateinit var getCredentialVersionByUUID_returns: CredentialView
    override fun getCredentialVersionByUUID(credentialUUID: String): CredentialView {
        getCredentialVersionByUUID_calledWithCredentialUUID = credentialUUID
        return getCredentialVersionByUUID_returns
    }
}
