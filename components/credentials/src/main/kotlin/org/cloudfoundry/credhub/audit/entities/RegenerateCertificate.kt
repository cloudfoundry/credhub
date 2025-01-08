package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class RegenerateCertificate : RequestDetails {
    var transitional: Boolean? = null

    override fun operation(): OperationDeviceAction = OperationDeviceAction.REGENERATE_CERTIFICATE
}
