package org.cloudfoundry.credhub.controllers.v1.management

import org.cloudfoundry.credhub.ManagementService

class SpyManagementService : ManagementService {

    var toggleReadOnlyMode__calledWith_shouldUseReadOnlyMode = false
    override fun toggleReadOnlyMode(shouldUseReadOnlyMode: Boolean) {
        toggleReadOnlyMode__calledWith_shouldUseReadOnlyMode = shouldUseReadOnlyMode
    }

    var isReadOnlyMode__returns_boolean = false
    override fun isReadOnlyMode(): Boolean {
        return isReadOnlyMode__returns_boolean
    }
}
