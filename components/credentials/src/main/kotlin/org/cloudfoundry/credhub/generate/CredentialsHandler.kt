package org.cloudfoundry.credhub.generate

import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse

interface CredentialsHandler {
    fun deleteCredential(credentialName: String)
    fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse
    fun getAllCredentialVersions(credentialName: String): DataResponse
    fun getCurrentCredentialVersions(credentialName: String): DataResponse
    fun getCredentialVersionByUUID(credentialUUID: String): CredentialView
}
