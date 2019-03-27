package org.cloudfoundry.credhub.controllers.autodocs.v1.credentials

import org.cloudfoundry.credhub.testdoubles.LegacyGenerationHandler
import org.cloudfoundry.credhub.views.CredentialView
import java.io.InputStream

class SpyLegacyGenerationHandler : LegacyGenerationHandler {
    lateinit var auditedHandlePostRequest_calledWithInputStream: InputStream
    lateinit var auditedHandlePostRequest_returns: CredentialView
    override fun auditedHandlePostRequest(inputStream: InputStream): CredentialView {
        auditedHandlePostRequest_calledWithInputStream = inputStream
        return auditedHandlePostRequest_returns
    }
}
