package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class RegenerateCredential : RequestDetails {
    var name: String? = null

    override fun operation(): OperationDeviceAction = OperationDeviceAction.REGENERATE
}
