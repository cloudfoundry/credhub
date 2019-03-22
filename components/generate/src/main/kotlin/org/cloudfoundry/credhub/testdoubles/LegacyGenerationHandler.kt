package org.cloudfoundry.credhub.testdoubles

import org.cloudfoundry.credhub.views.CredentialView
import java.io.InputStream

interface LegacyGenerationHandler {
    fun auditedHandlePostRequest(inputStream: InputStream): CredentialView
}
