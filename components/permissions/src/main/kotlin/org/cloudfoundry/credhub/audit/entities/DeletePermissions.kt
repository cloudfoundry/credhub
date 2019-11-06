package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class DeletePermissions(credentialName: String, actor: String) : RequestDetails {

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.DELETE_PERMISSIONS
    }
}
