package org.cloudfoundry.credhub.regenerate

import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import tools.jackson.databind.JsonNode

@Service
@Profile("remote")
class RemoteRegenerateHandler : RegenerateHandler {
    override fun handleRegenerate(
        credentialName: String,
        credentialMetadata: JsonNode?,
    ): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleBulkRegenerate(signerName: String): BulkRegenerateResults {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}
