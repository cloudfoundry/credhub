package org.cloudfoundry.credhub.controllers.v1.certificates

import org.cloudfoundry.credhub.certificates.CertificatesHandler
import org.cloudfoundry.credhub.exceptions.InvalidKeyLengthCertificateException
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView

class SpyCertificatesHandler : CertificatesHandler {
    lateinit var handleregenerateCalledwithCredentialuuid: String
    lateinit var handleregenerateCalledwithRequest: CertificateRegenerateRequest
    lateinit var handleregenerateReturnsCredentialview: CredentialView

    override fun handleRegenerate(
        credentialUuid: String,
        request: CertificateRegenerateRequest,
    ): CredentialView {
        handleregenerateCalledwithCredentialuuid = credentialUuid
        handleregenerateCalledwithRequest = request
        if (!listOf(2048,3072,4096).contains(request.keyLength)) throw InvalidKeyLengthCertificateException()
        return handleregenerateReturnsCredentialview
    }

    lateinit var handlegetallrequestReturnsCertificatecredentialsview: CertificateCredentialsView

    override fun handleGetAllRequest(): CertificateCredentialsView = handlegetallrequestReturnsCertificatecredentialsview

    lateinit var handlegetbynamerequestCalledwithName: String
    lateinit var handlegetbynamerequestReturnsCertificatecredentialsview: CertificateCredentialsView

    override fun handleGetByNameRequest(name: String): CertificateCredentialsView {
        handlegetbynamerequestCalledwithName = name
        return handlegetbynamerequestReturnsCertificatecredentialsview
    }

    lateinit var handlegetallversionsrequestCalledwithUuid: String
    var handlegetallversionsrequestCalledwithCurrent = false
    lateinit var handlegetallversionsrequestReturnsCertificateviews: List<CertificateView>

    override fun handleGetAllVersionsRequest(
        certificateId: String,
        current: Boolean,
    ): List<CertificateView> {
        handlegetallversionsrequestCalledwithUuid = certificateId
        handlegetallversionsrequestCalledwithCurrent = current

        return handlegetallversionsrequestReturnsCertificateviews
    }

    lateinit var handledeleteversionrequestCalledwithCertificateid: String
    lateinit var handledeleteversionrequestCalledwithVersionid: String
    lateinit var handledeleteversionrequestReturnsCertificateview: CertificateView

    override fun handleDeleteVersionRequest(
        certificateId: String,
        versionId: String,
    ): CertificateView {
        handledeleteversionrequestCalledwithCertificateid = certificateId
        handledeleteversionrequestCalledwithVersionid = versionId

        return handledeleteversionrequestReturnsCertificateview
    }

    lateinit var handleupdatetransitionalversionCalledwithCertificateid: String
    lateinit var handleupdatetransitionalversionCalledwithRequestbody: UpdateTransitionalVersionRequest
    lateinit var handleupdatetransitionalversionReturnsCertificateviewlist: List<CertificateView>

    override fun handleUpdateTransitionalVersion(
        certificateId: String,
        requestBody: UpdateTransitionalVersionRequest,
    ): List<CertificateView> {
        handleupdatetransitionalversionCalledwithCertificateid = certificateId
        handleupdatetransitionalversionCalledwithRequestbody = requestBody
        return handleupdatetransitionalversionReturnsCertificateviewlist
    }

    lateinit var handlecreateversionrequestCalledwithCertificateid: String
    lateinit var handlecreateversionrequestCalledwithRequestbody: CreateVersionRequest
    lateinit var handlecreateversionrequestReturnsCertificateview: CertificateView

    override fun handleCreateVersionsRequest(
        certificateId: String,
        requestBody: CreateVersionRequest,
    ): CertificateView {
        handlecreateversionrequestCalledwithCertificateid = certificateId
        handlecreateversionrequestCalledwithRequestbody = requestBody

        return handlecreateversionrequestReturnsCertificateview
    }
}
