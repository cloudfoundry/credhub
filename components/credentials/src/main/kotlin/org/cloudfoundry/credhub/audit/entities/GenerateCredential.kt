package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction

class GenerateCredential : SetCredential() {
    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.GENERATE
    }
}
