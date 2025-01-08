package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class GetCredentialById(
    val uuid: String,
) : RequestDetails {
    override fun operation(): OperationDeviceAction = OperationDeviceAction.GET
}
