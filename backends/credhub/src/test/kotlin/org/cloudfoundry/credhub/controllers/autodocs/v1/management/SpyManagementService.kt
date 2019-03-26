package org.cloudfoundry.credhub.controllers.autodocs.v1.management

import org.cloudfoundry.credhub.ManagementService

class SpyManagementService : ManagementService {

    var toggleReadOnlyMode_calledWithShouldUseReadOnlyMode = false
    override fun toggleReadOnlyMode(shouldUseReadOnlyMode: Boolean) {
        toggleReadOnlyMode_calledWithShouldUseReadOnlyMode = shouldUseReadOnlyMode
    }

    var isReadOnlyMode_returns = false
    override fun isReadOnlyMode(): Boolean {
        return isReadOnlyMode_returns
    }
}
