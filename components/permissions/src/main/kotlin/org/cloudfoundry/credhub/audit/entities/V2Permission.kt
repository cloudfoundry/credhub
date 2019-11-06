package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class V2Permission(var path: String, var actor: String, var operations: List<PermissionOperation>, var action: OperationDeviceAction) : RequestDetails {

    override fun operation(): OperationDeviceAction {
        return action
    }
}
