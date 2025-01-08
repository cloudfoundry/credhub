package org.cloudfoundry.credhub.controllers.v1.management

import org.cloudfoundry.credhub.ManagementService

class SpyManagementService : ManagementService {
    var togglereadonlymodeCalledwithShouldusereadonlymode = false

    override fun toggleReadOnlyMode(shouldUseReadOnlyMode: Boolean) {
        togglereadonlymodeCalledwithShouldusereadonlymode = shouldUseReadOnlyMode
    }

    var readonlymodeReturnsBoolean = false

    override fun isReadOnlyMode(): Boolean = readonlymodeReturnsBoolean
}
