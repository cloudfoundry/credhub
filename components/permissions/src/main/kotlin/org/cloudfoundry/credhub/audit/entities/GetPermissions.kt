package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class GetPermissions(credentialName: String) : RequestDetails {

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.GET_PERMISSIONS
    }
}
