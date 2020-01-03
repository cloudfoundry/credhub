package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class GetAllCertificates : RequestDetails {
    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.GET_ALL_CERTIFICATES
    }
}
