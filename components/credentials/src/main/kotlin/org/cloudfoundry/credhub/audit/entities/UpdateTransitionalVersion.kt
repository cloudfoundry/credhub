package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class UpdateTransitionalVersion : RequestDetails {
    var version: String? = null

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.UPDATE_TRANSITIONAL_VERSION
    }
}
