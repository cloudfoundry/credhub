package org.cloudfoundry.credhub.controllers.v1.regenerate

import com.fasterxml.jackson.databind.JsonNode
import org.cloudfoundry.credhub.regenerate.RegenerateHandler
import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView

class SpyRegenerateHandler : RegenerateHandler {

    var handleRegenerate__calledWith_credentialName: String? = null
    var handleRegenerate__calledWith_credentialMetadata: JsonNode? = null
    lateinit var handleRegenerate__returns_credentialView: CredentialView
    override fun handleRegenerate(credentialName: String, credentialMetadata: JsonNode?): CredentialView {
        handleRegenerate__calledWith_credentialName = credentialName
        handleRegenerate__calledWith_credentialMetadata = credentialMetadata

        return handleRegenerate__returns_credentialView
    }

    var handleBulkRegenerate__calledWith_signerName: String? = null
    lateinit var handleBulkRegenerate__returns_bulkRegenerateResults: BulkRegenerateResults
    override fun handleBulkRegenerate(signerName: String): BulkRegenerateResults {
        handleBulkRegenerate__calledWith_signerName = signerName

        return handleBulkRegenerate__returns_bulkRegenerateResults
    }
}
