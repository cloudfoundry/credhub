package org.cloudfoundry.credhub.handlers

import org.cloudfoundry.credhub.views.CredentialView
import java.io.InputStream

class DummyLegacyGenerationHandler : LegacyGenerationHandler {
    override fun auditedHandlePostRequest(inputStream: InputStream): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}
