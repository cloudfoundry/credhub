package org.cloudfoundry.credhub.controllers.v1.credentials

import org.cloudfoundry.credhub.credentials.CredentialsHandler
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse
import org.cloudfoundry.credhub.views.FindCredentialResult

class SpyCredentialsHandler : CredentialsHandler {
    lateinit var findstartingwithpathReturnsFindcredentialresultlist: List<FindCredentialResult>
    lateinit var findstartingwithpathCalledwithPath: String
    lateinit var findstartingwithpathCalledwithExpireswithindays: String

    override fun findStartingWithPath(
        path: String,
        expiresWithinDays: String,
    ): List<FindCredentialResult> {
        findstartingwithpathCalledwithPath = path
        findstartingwithpathCalledwithExpireswithindays = expiresWithinDays

        return findstartingwithpathReturnsFindcredentialresultlist
    }

    lateinit var findcontainingnameCalledwithName: String
    lateinit var findcontainingnameCalledwithExpireswithindays: String
    lateinit var findcontainingnameReturnsFindcredentialresultlist: List<FindCredentialResult>

    override fun findContainingName(
        name: String,
        expiresWithinDays: String,
    ): List<FindCredentialResult> {
        findcontainingnameCalledwithName = name
        findcontainingnameCalledwithExpireswithindays = expiresWithinDays

        return findcontainingnameReturnsFindcredentialresultlist
    }

    lateinit var generatecredentialCalledwithGeneraterequest: BaseCredentialGenerateRequest
    lateinit var generatecredentialReturnsCredentialview: CredentialView

    override fun generateCredential(generateRequest: BaseCredentialGenerateRequest): CredentialView {
        generatecredentialCalledwithGeneraterequest = generateRequest
        return generatecredentialReturnsCredentialview
    }

    lateinit var credentialCalledwithSetrequest: BaseCredentialSetRequest<*>
    lateinit var credentialReturnsCredentialview: CredentialView

    override fun setCredential(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        credentialCalledwithSetrequest = setRequest
        return credentialReturnsCredentialview
    }

    lateinit var deletecredentialCalledwithCredentialname: String

    override fun deleteCredential(credentialName: String) {
        deletecredentialCalledwithCredentialname = credentialName
    }

    override fun getNCredentialVersions(
        credentialName: String,
        numberOfVersions: Int?,
    ): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getAllCredentialVersions(credentialName: String): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var currentcredentialversionsCalledwithCredentialname: String
    lateinit var currentcredentialversionsReturnsDataresponse: DataResponse

    override fun getCurrentCredentialVersions(credentialName: String): DataResponse {
        currentcredentialversionsCalledwithCredentialname = credentialName

        return currentcredentialversionsReturnsDataresponse
    }

    lateinit var credentialversionbyuuidCalledwithCredentialuuid: String
    lateinit var credentialversionbyuuidReturnsCredentialview: CredentialView

    override fun getCredentialVersionByUUID(credentialUUID: String): CredentialView {
        credentialversionbyuuidCalledwithCredentialuuid = credentialUUID
        return credentialversionbyuuidReturnsCredentialview
    }
}
