package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails
import org.cloudfoundry.credhub.requests.PermissionEntry

class AddPermission(credentialName: String?, permissions: List<PermissionEntry>?) : RequestDetails {

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.ADD_PERMISSIONS
    }
}
