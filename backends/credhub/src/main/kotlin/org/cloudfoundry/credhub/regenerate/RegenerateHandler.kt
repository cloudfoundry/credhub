package org.cloudfoundry.credhub.regenerate

import com.fasterxml.jackson.databind.JsonNode
import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView

interface RegenerateHandler {
    fun handleRegenerate(credentialName: String, credentialMetadata: JsonNode?): CredentialView
    fun handleBulkRegenerate(signerName: String): BulkRegenerateResults
}
