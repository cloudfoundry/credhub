package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.view.CredentialView
import org.cloudfoundry.credhub.view.DataResponse

class DummyCredentialsHandler: CredentialsHandler {
    override fun deleteCredential(credentialName: String) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getAllCredentialVersions(credentialName: String): DataResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getCurrentCredentialVersions(credentialName: String): DataResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getCredentialVersionByUUID(credentialUUID: String): CredentialView {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}