package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.view.CredentialView
import java.io.InputStream

class DummyLegacyGenerationHandler: LegacyGenerationHandler {
    override fun auditedHandlePostRequest(inputStream: InputStream): CredentialView {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}