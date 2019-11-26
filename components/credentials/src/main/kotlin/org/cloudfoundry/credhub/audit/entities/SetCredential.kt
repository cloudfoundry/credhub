package org.cloudfoundry.credhub.audit.entities

import java.util.Objects
import org.apache.commons.lang3.builder.EqualsBuilder
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

open class SetCredential : RequestDetails {
    var name: String? = null
    var type: String? = null

    constructor(credentialName: String, credentialType: String) : super() {
        name = credentialName
        type = credentialType
    }

    constructor() : super() {
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as SetCredential?

        return EqualsBuilder()
            .append(name, that!!.name)
            .append(type, that.type)
            .isEquals
    }

    override fun hashCode(): Int {
        return Objects.hash(name, type)
    }

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.SET
    }
}
