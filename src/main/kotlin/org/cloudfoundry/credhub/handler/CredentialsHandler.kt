package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.view.CredentialView
import org.cloudfoundry.credhub.view.DataResponse

interface CredentialsHandler {
    fun deleteCredential(credentialName: String)
    fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse
    fun getAllCredentialVersions(credentialName: String): DataResponse
    fun getCurrentCredentialVersions(credentialName: String): DataResponse
    fun getCredentialVersionByUUID(credentialUUID: String): CredentialView
}
