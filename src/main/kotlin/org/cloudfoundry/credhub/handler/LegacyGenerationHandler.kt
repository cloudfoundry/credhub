package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.view.CredentialView
import java.io.InputStream

interface LegacyGenerationHandler {
    fun auditedHandlePostRequest(inputStream: InputStream): CredentialView
}
