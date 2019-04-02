package org.cloudfoundry.credhub.controllers.v1.credentials

import org.cloudfoundry.credhub.generate.LegacyGenerationHandler
import org.cloudfoundry.credhub.views.CredentialView
import java.io.InputStream

class SpyLegacyGenerationHandler : LegacyGenerationHandler {
    lateinit var auditedHandlePostRequest__calledWith_inputStream: InputStream
    lateinit var auditedHandlePostRequest__returns_credentialView: CredentialView
    override fun auditedHandlePostRequest(inputStream: InputStream): CredentialView {
        auditedHandlePostRequest__calledWith_inputStream = inputStream
        return auditedHandlePostRequest__returns_credentialView
    }
}
