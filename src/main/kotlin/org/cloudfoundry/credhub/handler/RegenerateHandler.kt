package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.view.BulkRegenerateResults
import org.cloudfoundry.credhub.view.CredentialView

interface RegenerateHandler {
    fun handleRegenerate(credentialName: String): CredentialView
    fun handleBulkRegenerate(signerName: String): BulkRegenerateResults
}
