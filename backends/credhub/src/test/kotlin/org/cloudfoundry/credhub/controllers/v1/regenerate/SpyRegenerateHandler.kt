package org.cloudfoundry.credhub.controllers.v1.regenerate

import org.cloudfoundry.credhub.regenerate.RegenerateHandler
import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView
import tools.jackson.databind.JsonNode

class SpyRegenerateHandler : RegenerateHandler {
    var handleRegenerateCalledWithCredentialName: String? = null
    var handleRegenerateCalledWithCredentialMetadata: JsonNode? = null
    lateinit var handleregenerateReturnsCredentialview: CredentialView

    override fun handleRegenerate(
        credentialName: String,
        credentialMetadata: JsonNode?,
    ): CredentialView {
        handleRegenerateCalledWithCredentialName = credentialName
        handleRegenerateCalledWithCredentialMetadata = credentialMetadata

        return handleregenerateReturnsCredentialview
    }

    var handleBulkRegenerateCalledWithSignerName: String? = null
    lateinit var handleBulkRegenerateReturnsBulkRegenerateResults: BulkRegenerateResults

    override fun handleBulkRegenerate(signerName: String): BulkRegenerateResults {
        handleBulkRegenerateCalledWithSignerName = signerName

        return handleBulkRegenerateReturnsBulkRegenerateResults
    }
}
