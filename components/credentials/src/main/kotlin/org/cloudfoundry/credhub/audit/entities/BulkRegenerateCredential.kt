package org.cloudfoundry.credhub.audit.entities

import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class BulkRegenerateCredential : RequestDetails {
    var signedBy: String? = null

    constructor() : super() {
    }

    constructor(signedBy: String) : super() {
        this.signedBy = signedBy
    }

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.BULK_REGENERATE
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as BulkRegenerateCredential?

        return EqualsBuilder()
            .append(signedBy, that!!.signedBy)
            .isEquals
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(17, 37)
            .append(signedBy)
            .toHashCode()
    }
}
