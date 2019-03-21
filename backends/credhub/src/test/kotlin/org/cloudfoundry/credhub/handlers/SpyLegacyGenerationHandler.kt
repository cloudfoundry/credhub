package org.cloudfoundry.credhub.handlers

import org.cloudfoundry.credhub.views.CredentialView
import java.io.InputStream

class SpyLegacyGenerationHandler : LegacyGenerationHandler {
    lateinit var auditedHandlePostRequest_calledWithInputStream : InputStream
    lateinit var auditedHandlePostRequest_returns : CredentialView
    override fun auditedHandlePostRequest(inputStream: InputStream): CredentialView {
        auditedHandlePostRequest_calledWithInputStream = inputStream
        return auditedHandlePostRequest_returns
    }
}
