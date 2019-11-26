package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class DeleteCredential : RequestDetails {
    var name: String? = null

    constructor() : super() {
    }

    constructor(name: String) : super() {
        this.name = name
    }

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.DELETE
    }
}
