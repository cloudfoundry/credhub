package org.cloudfoundry.credhub.audit.entities

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

@JsonIgnoreProperties(ignoreUnknown = true)
class InterpolateCredentials : RequestDetails {
    override fun operation(): OperationDeviceAction = OperationDeviceAction.INTERPOLATE
}
