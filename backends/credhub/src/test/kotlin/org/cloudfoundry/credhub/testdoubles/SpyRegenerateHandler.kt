package org.cloudfoundry.credhub.testdoubles

import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView

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
