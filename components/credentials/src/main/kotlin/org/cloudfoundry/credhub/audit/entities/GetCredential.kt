package org.cloudfoundry.credhub.audit.entities

import java.util.Objects
import org.apache.commons.lang3.builder.EqualsBuilder
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails

class GetCredential : RequestDetails {
    var name: String? = null
    var versions: Int? = null
    var current: Boolean? = null

    constructor(credentialName: String, numberOfVersions: Int?, current: Boolean) : super() {
        name = credentialName
        versions = numberOfVersions
        this.current = current
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

        val that = o as GetCredential?

        return EqualsBuilder()
            .append(name, that!!.name)
            .append(versions, that.versions)
            .append(current, that.current)
            .isEquals
    }

    override fun hashCode(): Int {
        return Objects.hash(name, versions, current)
    }

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.GET
    }
}
