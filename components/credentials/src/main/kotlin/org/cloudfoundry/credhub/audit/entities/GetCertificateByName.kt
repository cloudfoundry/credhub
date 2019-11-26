package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class GetCertificateByName : RequestDetails {
    var name: String? = null

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.GET_CERTIFICATE
    }
}
