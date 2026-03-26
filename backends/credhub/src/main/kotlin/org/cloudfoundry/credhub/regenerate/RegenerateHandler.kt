package org.cloudfoundry.credhub.regenerate

import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView
import tools.jackson.databind.JsonNode

interface RegenerateHandler {
    fun handleRegenerate(
        credentialName: String,
        credentialMetadata: JsonNode?,
    ): CredentialView

    fun handleBulkRegenerate(signerName: String): BulkRegenerateResults
}
