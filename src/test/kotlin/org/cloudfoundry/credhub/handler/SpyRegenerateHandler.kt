package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.view.BulkRegenerateResults
import org.cloudfoundry.credhub.view.CredentialView

class SpyRegenerateHandler : RegenerateHandler {

    var handleRegenerate_calledWithCredentialName: String? = null
    override fun handleRegenerate(credentialName: String): CredentialView {
        handleRegenerate_calledWithCredentialName = credentialName

        return CredentialView()
    }

    var handleBulkRegenerate_calledWithSignerName: String? = null
    override fun handleBulkRegenerate(signerName: String): BulkRegenerateResults {
        handleBulkRegenerate_calledWithSignerName = signerName

        return BulkRegenerateResults()
    }
}
