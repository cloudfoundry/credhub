package org.cloudfoundry.credhub.audit.entities

import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class FindCredential : RequestDetails {
    var nameLike: String? = null
    var path: String? = null
    var paths: Boolean? = null

    var expiresWithinDays: String? = null

    override fun operation(): OperationDeviceAction = OperationDeviceAction.FIND
}
